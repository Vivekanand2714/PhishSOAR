"""
Microsoft Outlook Connector Module
==================================
Handles OAuth 2.0 authentication via MSAL (Microsoft Authentication Library)
and Microsoft Graph API to fetch and quarantine phishing emails from Outlook/Office 365.

Includes a built-in realistic simulator when credentials are not configured.
"""

import os
import json
import logging
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import msal

from config import (
    OUTLOOK_CLIENT_ID, OUTLOOK_CLIENT_SECRET, OUTLOOK_TENANT_ID,
    OUTLOOK_TOKEN_FILE, OUTLOOK_SCOPES
)

logger = logging.getLogger(__name__)

# Standard redirect URI for desktop applications
REDIRECT_URI = "http://localhost:5001"

def get_outlook_token(account_email: str = None) -> Optional[str]:
    """
    Authenticate with Microsoft Graph API using MSAL.
    Returns the Access Token string or None.
    """
    if not OUTLOOK_CLIENT_ID:
        logger.warning("Outlook client credentials not configured — running in SIMULATOR mode")
        return None

    authority = f"https://login.microsoftonline.com/{OUTLOOK_TENANT_ID or 'common'}"
    token_file = os.path.join(os.path.dirname(OUTLOOK_TOKEN_FILE), f"token_outlook_{account_email}.json") if account_email else OUTLOOK_TOKEN_FILE
    
    # Check for confidential vs public client
    if OUTLOOK_CLIENT_SECRET:
        # Confidential client flow
        app = msal.ConfidentialClientApplication(
            OUTLOOK_CLIENT_ID,
            client_credential=OUTLOOK_CLIENT_SECRET,
            authority=authority
        )
    else:
        # Public client flow
        app = msal.PublicClientApplication(
            OUTLOOK_CLIENT_ID,
            authority=authority
        )

    # Try loading cached token
    token_cache = msal.SerializableTokenCache()
    if os.path.exists(token_file):
        with open(token_file, "r") as f:
            token_cache.deserialize(f.read())
            
    # Re-instantiate app with cache
    if OUTLOOK_CLIENT_SECRET:
        app = msal.ConfidentialClientApplication(
            OUTLOOK_CLIENT_ID,
            client_credential=OUTLOOK_CLIENT_SECRET,
            authority=authority,
            token_cache=token_cache
        )
    else:
        app = msal.PublicClientApplication(
            OUTLOOK_CLIENT_ID,
            authority=authority,
            token_cache=token_cache
        )

    # Try silently acquiring token from cache
    accounts = app.get_accounts()
    if accounts:
        logger.info(f"Acquiring Microsoft token silently for account: {accounts[0]['username']}")
        result = app.acquire_token_silent(OUTLOOK_SCOPES, account=accounts[0])
        if result and "access_token" in result:
            return result["access_token"]

    # Silent acquire failed, do interactive auth
    try:
        logger.info("Opening browser for Microsoft interactive auth on port 5001...")
        # MSAL supports starting a local HTTP server on port 5001 to capture redirect code
        result = app.acquire_token_interactive(
            scopes=OUTLOOK_SCOPES,
            port=5001
        )
        
        if result and "access_token" in result:
            # Save cache
            if token_cache.has_state_changed:
                with open(token_file, "w") as f:
                    f.write(token_cache.serialize())
            logger.info(f"Microsoft Outlook token successfully acquired and cached to {token_file}")
            return result["access_token"]
            
        if "error" in result:
            logger.error(f"MSAL authentication error: {result.get('error_description')}")
    except Exception as e:
        logger.error(f"Interactive Microsoft OAuth flow failed: {e}")
        
    return None


def fetch_unread_outlook_emails(account_email: str = None) -> List[dict]:
    """
    Fetch unread emails from Outlook Inbox.
    Returns standard parsed email list.
    """
    token = get_outlook_token(account_email)
    if not token:
        # Fall back to simulated email for demo testing
        return [get_simulated_outlook_email()]

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    # Fetch messages matching isRead eq false
    url = "https://graph.microsoft.com/v1.0/me/mailFolders/Inbox/messages?$filter=isRead eq false"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            messages = resp.json().get("value", [])
            logger.info(f"Fetched {len(messages)} unread emails from Outlook")
            
            parsed_emails = []
            for msg in messages:
                parsed = _parse_outlook_message(msg, headers)
                if parsed:
                    parsed_emails.append(parsed)
            return parsed_emails
        else:
            logger.error(f"Graph API returned error: {resp.status_code} - {resp.text}")
    except Exception as e:
        logger.error(f"Outlook Graph API request failed: {e}")
        
    return []


def quarantine_outlook_email(msg_id: str) -> dict:
    """
    Quarantine an Outlook message by moving it to the Deleted Items folder.
    """
    result = {"msg_id": msg_id, "actions": [], "success": False}
    token = get_outlook_token()
    
    if not token:
        # Simulator quarantine
        result["actions"].append("Simulated: Outlook message moved to Deleted Items folder")
        result["actions"].append("Simulated: Marked as read")
        result["success"] = True
        logger.info(f"Outlook Email {msg_id} quarantined successfully (Simulator)")
        return result

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Microsoft Graph API: move message to Deleted Items (built-in folder 'deleteditems')
    url = f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}/move"
    try:
        # Move message
        resp = requests.post(url, headers=headers, json={"destinationId": "deleteditems"}, timeout=10)
        if resp.status_code in (200, 201):
            result["actions"].append("Moved to Deleted Items folder")
            
            # Also mark as read (so it doesn't poll again)
            patch_url = f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}"
            requests.patch(patch_url, headers=headers, json={"isRead": True}, timeout=10)
            result["actions"].append("Marked as read")
            
            result["success"] = True
            logger.info(f"Outlook Email {msg_id} successfully moved to Deleted Items folder")
        else:
            logger.error(f"Failed to move Outlook message: {resp.status_code} - {resp.text}")
            result["error"] = resp.text
    except Exception as e:
        logger.error(f"Microsoft Graph API request failed: {e}")
        result["error"] = str(e)
        
    return result


def _parse_outlook_message(msg: dict, headers: dict) -> Optional[dict]:
    """Parse Outlook Graph API message to standardized schema."""
    try:
        msg_id = msg.get("id", "")
        subject = msg.get("subject", "")
        body_plain = msg.get("body", {}).get("content", "") if msg.get("body", {}).get("contentType") == "text" else ""
        body_html = msg.get("body", {}).get("content", "") if msg.get("body", {}).get("contentType") == "html" else ""
        
        sender_info = msg.get("sender", {}).get("emailAddress", {})
        sender_name = sender_info.get("name", "")
        sender_email = sender_info.get("address", "")
        sender = f"{sender_name} <{sender_email}>" if sender_name else sender_email

        to_recipients = msg.get("toRecipients", [])
        to = ", ".join(r.get("emailAddress", {}).get("address", "") for r in to_recipients)
        
        date = msg.get("receivedDateTime", "")

        # Fetch attachments if present
        attachments = []
        if msg.get("hasAttachments", False):
            att_url = f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}/attachments"
            att_resp = requests.get(att_url, headers=headers, timeout=10)
            if att_resp.status_code == 200:
                for att in att_resp.json().get("value", []):
                    attachments.append({
                        "filename": att.get("name", "attachment"),
                        "mimeType": att.get("contentType", "application/octet-stream"),
                        "size": att.get("size", 0),
                        "attachmentId": att.get("id", ""),
                        "messageId": msg_id
                    })

        return {
            "id":           msg_id,
            "thread_id":    msg.get("conversationId"),
            "snippet":      msg.get("bodyPreview", ""),
            "from":         sender,
            "to":           to,
            "subject":      subject,
            "date":         date,
            "reply_to":     sender_email,  # Fallback
            "return_path":  "",
            "received":     "",
            "body_plain":   body_plain,
            "body_html":    body_html,
            "attachments":  attachments,
            "raw_headers":  {
                "from":         sender,
                "to":           to,
                "subject":      subject,
            }
        }
    except Exception as e:
        logger.error(f"Error parsing Outlook message: {e}", exc_info=True)
        return None


def get_simulated_outlook_email() -> dict:
    """Returns a realistic simulated phishing email for Outlook."""
    return {
        "id":          "outlook-sim-001",
        "thread_id":   "thread-outlook-sim-001",
        "snippet":     "Your Microsoft 365 account requires immediate password update.",
        "from":        "Microsoft Security Support <no-reply@office365-verify.com>",
        "to":          "employee@company.com",
        "subject":     "⚠️ URGENT: Update your Microsoft 365 Password Immediately",
        "date":        datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000"),
        "reply_to":    "support@office365-verify.com",
        "return_path": "<support@office365-verify.com>",
        "received":    "from mail.office365-verify.com (198.51.100.42)",
        "body_plain":  """Dear Office 365 User,

We noticed suspicious login attempts to your account.
To secure your account, you must update your password immediately by clicking below:

http://login.office365.com.phishing-portal.net/update-password

Failure to do so will result in email suspension.

Sincerely,
Microsoft Security Team
""",
        "body_html":   """<html><body>
<p>Dear Office 365 User,</p>
<p>We noticed suspicious login attempts. <a href="http://login.office365.com.phishing-portal.net/update-password">Click here to update your password</a></p>
</body></html>""",
        "attachments": [],
        "raw_headers": {
            "from":         "no-reply@office365-verify.com",
            "to":           "employee@company.com",
            "subject":      "⚠️ URGENT: Update your Microsoft 365 Password Immediately",
        }
    }
