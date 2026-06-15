"""
SOAR SQLite Database Manager
=============================
Handles local storage and querying for accounts and emails.
Enables persistence and instant display of triaged email classifications.
"""

import os
import sqlite3
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soar_mail.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database schema."""
    logger.info(f"Initializing database at: {DB_PATH}")
    conn = get_db_connection()
    cursor = conn.cursor()

    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON;")

    # Create accounts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        provider TEXT NOT NULL,          -- 'gmail', 'outlook', 'mock'
        status TEXT DEFAULT 'linked',    -- 'linked', 'active', 'disconnected'
        token_data TEXT                  -- Serialized token JSON (if applicable)
    );
    """)

    # Create emails table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS emails (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        subject TEXT,
        date TEXT,
        body_plain TEXT,
        body_html TEXT,
        snippet TEXT,
        folder TEXT DEFAULT 'inbox',     -- 'inbox', 'marketing', 'spam', 'archive', 'malicious', 'suspicious'
        verdict TEXT DEFAULT 'CLEAN',    -- 'MALICIOUS', 'SUSPICIOUS', 'CLEAN'
        score INTEGER DEFAULT 0,
        ticket_id TEXT,
        gemma_advisory TEXT,
        processed_at TEXT,
        is_read INTEGER DEFAULT 0,
        FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
    );
    """)

    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")


def add_account(email: str, provider: str, status: str = "linked", token_data: dict = None) -> str:
    """Adds a new email account to manage."""
    conn = get_db_connection()
    cursor = conn.cursor()
    account_id = f"acc_{str(uuid.uuid4())[:8]}"
    token_str = json.dumps(token_data) if token_data else None

    try:
        cursor.execute(
            "INSERT INTO accounts (id, email, provider, status, token_data) VALUES (?, ?, ?, ?, ?)",
            (account_id, email, provider.lower(), status, token_str)
        )
        conn.commit()
        logger.info(f"Account {email} ({provider}) added with ID: {account_id}")
        return account_id
    except sqlite3.IntegrityError:
        # Account already exists, fetch existing ID
        cursor.execute("SELECT id FROM accounts WHERE email = ?", (email,))
        row = cursor.fetchone()
        if row:
            account_id = row["id"]
            # Update token if provided
            if token_str:
                cursor.execute("UPDATE accounts SET token_data = ?, status = ? WHERE id = ?", (token_str, status, account_id))
                conn.commit()
            return account_id
    finally:
        conn.close()
    return account_id


def delete_account(account_id: str):
    """Deletes an account and its associated emails."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")
    try:
        cursor.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        conn.commit()
        logger.info(f"Account {account_id} deleted successfully.")
    finally:
        conn.close()


def get_accounts() -> List[Dict[str, Any]]:
    """Retrieves all linked email accounts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, provider, status FROM accounts")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_account_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieves account details by email address."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def route_folder(verdict: str, subject: str, body: str) -> str:
    """Categorizes an email into a standard folder based on verdict and keywords."""
    if verdict == "MALICIOUS":
        return "malicious"
    if verdict == "SUSPICIOUS":
        return "suspicious"

    text = f"{subject or ''} {body or ''}".lower()
    
    # Marketing keywords
    marketing_keywords = ["deal", "discount", "sale", "newsletter", "offer", "coupon", "marketing", "subscribe", "promo"]
    if any(kw in text for kw in marketing_keywords):
        return "marketing"
        
    # Spam keywords
    spam_keywords = ["lottery", "win cash", "free prize", "viagra", "casino", "jackpot", "invest now"]
    if any(kw in text for kw in spam_keywords):
        return "spam"
        
    return "inbox"


def save_email(
    email_data: dict,
    account_id: str,
    verdict: str,
    score: int,
    ticket_id: str,
    gemma_advisory: str,
    folder: str = None
) -> str:
    """Saves or updates a triaged email inside the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    subject = email_data.get("subject", "")
    body_plain = email_data.get("body_plain", "")
    
    if not folder:
        folder = route_folder(verdict, subject, body_plain)

    msg_id = email_data.get("id")
    processed_at = datetime.now(timezone.utc).isoformat()

    try:
        cursor.execute("""
            INSERT INTO emails (
                id, account_id, sender, recipient, subject, date, body_plain, body_html,
                snippet, folder, verdict, score, ticket_id, gemma_advisory, processed_at, is_read
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                folder = excluded.folder,
                verdict = excluded.verdict,
                score = excluded.score,
                ticket_id = excluded.ticket_id,
                gemma_advisory = excluded.gemma_advisory,
                processed_at = excluded.processed_at
        """, (
            msg_id,
            account_id,
            email_data.get("from", ""),
            email_data.get("to", ""),
            subject,
            email_data.get("date", ""),
            body_plain,
            email_data.get("body_html", ""),
            email_data.get("snippet", ""),
            folder,
            verdict,
            score,
            ticket_id,
            gemma_advisory,
            processed_at,
            0  # is_read default to unread (0)
        ))
        conn.commit()
        logger.info(f"Email {msg_id} saved to folder '{folder}' with verdict {verdict}")
    except Exception as e:
        logger.error(f"Failed to save email {msg_id}: {e}", exc_info=True)
    finally:
        conn.close()
    return folder


def get_emails(account_id: str = None, folder: str = None) -> List[Dict[str, Any]]:
    """Retrieves emails filtered by account and/or folder."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT id, account_id, sender, recipient, subject, date, snippet, folder, verdict, score, is_read, processed_at FROM emails"
    params = []
    
    conditions = []
    if account_id:
        conditions.append("account_id = ?")
        params.append(account_id)
    if folder:
        conditions.append("folder = ?")
        params.append(folder)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY processed_at DESC"
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_email_details(email_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full body and ticket metadata for a specific email."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM emails WHERE id = ?", (email_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def mark_email_as_read(email_id: str):
    """Marks an email as read in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE emails SET is_read = 1 WHERE id = ?", (email_id,))
    conn.commit()
    conn.close()


def load_processed_emails_for_account(account_id: str) -> set:
    """Returns a set of all processed message IDs for a specific account."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM emails WHERE account_id = ?", (account_id,))
    rows = cursor.fetchall()
    conn.close()
    return set(r["id"] for r in rows)


# Initialize DB on load
init_db()
