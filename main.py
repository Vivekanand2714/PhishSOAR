"""
SOAR Playbook Orchestrator
===========================
Main entry point — orchestrates the full phishing response pipeline.
Runs all 5 modules in sequence and tracks execution state.

Pipeline stages:
  1. Gmail ingestion
  2. IoC extraction
  3. Threat intel enrichment
  4. Triage + decision
  5. Response actions
  6. Report generation

Usage:
  python main.py              # Process latest inbox email
  python main.py --demo       # Run with built-in phishing demo email
  python main.py --email-id X # Process specific Gmail message ID
"""

import os
import sys
import time
import json
import logging
import argparse
import threading
import random
import uuid
from datetime import datetime, timezone
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("SOAR")

# Shared state for web dashboard (thread-safe)
PLAYBOOK_STATE = {
    "running":     False,
    "stage":       "idle",
    "stages":      [],
    "result":      None,
    "started_at":  None,
    "elapsed":     0,
    "error":       None,
    "queue_size":  0,
    "queue_index": 0,
    "mode":        "idle",  # "idle" / "backfill" / "monitoring"
    "source":      "idle",  # "gmail" / "outlook" / "both"
}
STATE_LOCK = threading.Lock()
MONITOR_ACTIVE = False


def update_state(stage: str, status: str, data: dict = None):
    """Update shared playbook state (thread-safe)."""
    with STATE_LOCK:
        PLAYBOOK_STATE["stage"] = stage
        entry = {
            "name":      stage,
            "status":    status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data":      data or {}
        }
        # Update or append stage
        for existing in PLAYBOOK_STATE["stages"]:
            if existing["name"] == stage:
                existing.update(entry)
                return
        PLAYBOOK_STATE["stages"].append(entry)


def get_demo_email() -> dict:
    """Return a realistic phishing demo email for testing."""
    return {
        "id":          "demo-001",
        "thread_id":   "thread-demo-001",
        "snippet":     "Urgent: Your account has been compromised. Click here to verify.",
        "from":        "security-alert@paypaI-verify.tk",
        "to":          "victim@company.com",
        "subject":     "⚠️ URGENT: Your PayPal Account Has Been Suspended",
        "date":        datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000"),
        "reply_to":    "support@totally-not-phishing.xyz",
        "return_path": "<bounce@spammer-server.ga>",
        "received":    "from unknown-host-123.xyz (45.33.32.156)",
        "body_plain":  """Dear Valued Customer,

We have detected unusual activity on your PayPal account.
Your account has been temporarily suspended for your security.

To restore access, please click here immediately:
http://paypaI-secure-login.tk/verify?token=abc123&user=victim

If you do not verify within 24 hours, your account will be PERMANENTLY CLOSED.

Also, please download and complete the attached verification form:
See attachment: account_verification_form.exe

Your account details:
- Account: victim@company.com
- Last login from: 185.220.101.5 (suspicious IP)
- Status: SUSPENDED

Click here to verify your identity: http://login.paypaI.com.phishing-site.xyz/restore

Act now to avoid losing access to your PayPal account!

Best regards,
PayPal Security Team
security@paypaI-verify.tk
""",
        "body_html":   """<html><body>
<p>Dear Valued Customer,</p>
<p>We have detected unusual activity. <a href="http://paypaI-secure-login.tk/verify?token=abc123">Click here to verify your account</a></p>
<p>Alternatively: <a href="http://login.paypaI.com.phishing-site.xyz/restore">http://www.paypal.com/restore</a></p>
<p>Download form: <a href="http://paypaI-secure-login.tk/form.exe">account_verification_form.exe</a></p>
</body></html>""",
        "attachments": [
            {
                "filename":     "account_verification_form.exe",
                "mimeType":     "application/x-msdownload",
                "size":         102400,
                "attachmentId": "demo-att-001",
                "messageId":    "demo-001"
            }
        ],
        "raw_headers": {
            "from":         "security-alert@paypaI-verify.tk",
            "to":           "victim@company.com",
            "subject":      "⚠️ URGENT: Your PayPal Account Has Been Suspended",
            "reply-to":     "support@totally-not-phishing.xyz",
            "return-path":  "<bounce@spammer-server.ga>",
            "received":     "from unknown-host-123.xyz (45.33.32.156)",
        }
    }


def run_playbook(
    email_data: Optional[dict] = None,
    gmail_service=None,
    email_id: Optional[str] = None,
    use_demo: bool = False,
    outlook_service=None,
    is_queue_run: bool = False
) -> dict:
    """
    Execute the full SOAR phishing response playbook.
    Returns complete result dict.
    """
    start_time = time.time()

    if not is_queue_run:
        with STATE_LOCK:
            PLAYBOOK_STATE.update({
                "running":    True,
                "stage":      "starting",
                "stages":     [],
                "result":     None,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "elapsed":    0,
                "error":      None,
            })

    try:
        # ═══════════════════════════════════════════════════════
        # STAGE 1: Email Ingestion
        # ═══════════════════════════════════════════════════════
        update_state("ingestion", "running")
        logger.info("=" * 60)
        logger.info("SOAR PHISHING PLAYBOOK — STARTING")
        logger.info("=" * 60)

        if use_demo:
            logger.info("Using demo phishing email")
            email_data = get_demo_email()
        elif email_data is None and gmail_service:
            logger.info("Fetching latest email from Gmail...")
            from gmail_connector import fetch_latest_phishing_email
            email_data = fetch_latest_phishing_email(gmail_service)
        elif email_data is None and email_id and gmail_service:
            from gmail_connector import fetch_email_by_id
            email_data = fetch_email_by_id(gmail_service, email_id)

        if not email_data:
            raise ValueError("No email to process — use --demo flag or check Gmail connection")

        update_state("ingestion", "complete", {
            "subject": email_data.get("subject", ""),
            "from":    email_data.get("from", ""),
            "has_attachments": len(email_data.get("attachments", [])) > 0
        })
        logger.info(f"Email ingested: '{email_data.get('subject', 'No subject')}'")

        # ═══════════════════════════════════════════════════════
        # STAGE 2: IoC Extraction
        # ═══════════════════════════════════════════════════════
        update_state("extraction", "running")
        logger.info("Stage 2: Extracting IoCs...")

        from email_parser import extract_iocs
        iocs = extract_iocs(email_data)

        update_state("extraction", "complete", {
            "urls":        len(iocs.get("urls", [])),
            "domains":     len(iocs.get("domains", [])),
            "attachments": len(iocs.get("attachments", [])),
            "keywords":    len(iocs.get("keywords_found", [])),
            "risks":       len(iocs.get("risk_indicators", [])),
        })
        logger.info(f"IoCs extracted: {len(iocs.get('urls',[]))} URLs, {len(iocs.get('domains',[]))} domains")

        # ═══════════════════════════════════════════════════════
        # STAGE 3: Threat Intel Enrichment
        # ═══════════════════════════════════════════════════════
        update_state("enrichment", "running")
        logger.info("Stage 3: Enriching IoCs via threat intel APIs...")

        from threat_intel import enrich_iocs
        enrichment = enrich_iocs(iocs)

        update_state("enrichment", "complete", {
            "total_checked": enrichment["summary"]["total_checked"],
            "malicious":     enrichment["summary"]["malicious"],
            "suspicious":    enrichment["summary"]["suspicious"],
            "clean":         enrichment["summary"]["clean"],
        })
        logger.info(f"Enrichment done: {enrichment['summary']['malicious']} malicious found")

        # ═══════════════════════════════════════════════════════
        # STAGE 4: Triage
        # ═══════════════════════════════════════════════════════
        update_state("triage", "running")
        logger.info("Stage 4: Running triage decision engine...")

        from triage import triage as run_triage
        triage_result = run_triage(iocs, enrichment)

        update_state("triage", "complete", {
            "verdict": triage_result["verdict"],
            "score":   triage_result["score"],
            "action":  triage_result["action"],
        })
        logger.info(f"Triage verdict: {triage_result['verdict']} (score: {triage_result['score']}/100)")

        # ═══════════════════════════════════════════════════════
        # STAGE 5: Response Actions
        # ═══════════════════════════════════════════════════════
        update_state("response", "running")
        logger.info("Stage 5: Executing response actions...")

        from response_actions import execute_response
        response_log = execute_response(gmail_service, email_data, iocs, triage_result, outlook_service)

        update_state("response", "complete", {
            "actions_taken": response_log.get("actions_taken", []),
            "quarantined":   response_log.get("actions", [{}])[0].get("status") == "SUCCESS" if response_log.get("actions") else False,
        })
        logger.info(f"Response actions: {response_log.get('actions_taken', [])}")

        # ═══════════════════════════════════════════════════════
        # STAGE 6: Report Generation
        # ═══════════════════════════════════════════════════════
        elapsed = time.time() - start_time
        update_state("reporting", "running")
        logger.info("Stage 6: Generating incident report...")

        # Generate local Gemma AI security advisory warning
        gemma_advisory = ""
        if triage_result.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
            try:
                from gemma_advisor import generate_gemma_advisory
                gemma_advisory = generate_gemma_advisory(
                    sender=email_data.get("from", ""),
                    subject=email_data.get("subject", ""),
                    verdict=triage_result.get("verdict", ""),
                    urls=iocs.get("urls", []),
                    attachments=[a.get("filename", "") for a in iocs.get("attachments", [])]
                )
            except Exception as e:
                logger.error(f"Gemma advisory generation failed: {e}")
                gemma_advisory = "Could not generate Gemma AI warning advisory."

        from report_generator import generate_report
        report = generate_report(email_data, iocs, enrichment, triage_result, response_log, elapsed, gemma_advisory)

        update_state("reporting", "complete", {
            "ticket_id": report["ticket_id"],
            "html_path": report["html_path"],
        })

        # ═══════════════════════════════════════════════════════
        # DONE
        # ═══════════════════════════════════════════════════════
        elapsed = time.time() - start_time
        logger.info("=" * 60)
        logger.info(f"PLAYBOOK COMPLETE in {elapsed:.1f}s")
        logger.info(f"Verdict: {triage_result['verdict']} | Score: {triage_result['score']}/100")
        logger.info(f"Ticket: {report['ticket_id']}")
        logger.info(f"Report: {report['html_path']}")
        logger.info("=" * 60)

        final_result = {
            "success":      True,
            "ticket_id":    report["ticket_id"],
            "verdict":      triage_result["verdict"],
            "score":        triage_result["score"],
            "elapsed_sec":  round(elapsed, 2),
            "within_sla":   elapsed <= 60,
            "html_path":    report["html_path"],
            "ticket_path":  report["ticket_path"],
            "ticket":       report["ticket"],
            "iocs":         iocs,
            "enrichment":   enrichment,
            "triage":       triage_result,
            "response":     response_log,
            "gemma_advisory": gemma_advisory
        }

        if not is_queue_run:
            with STATE_LOCK:
                PLAYBOOK_STATE["running"] = False
                PLAYBOOK_STATE["stage"]   = "complete"
                PLAYBOOK_STATE["result"]  = final_result
                PLAYBOOK_STATE["elapsed"] = round(elapsed, 2)

        return final_result

    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"Playbook failed: {e}", exc_info=True)
        error_result = {
            "success":     False,
            "error":       str(e),
            "elapsed_sec": round(elapsed, 2),
        }
        if not is_queue_run:
            with STATE_LOCK:
                PLAYBOOK_STATE["running"] = False
                PLAYBOOK_STATE["stage"]   = "error"
                PLAYBOOK_STATE["error"]   = str(e)
                PLAYBOOK_STATE["result"]  = error_result
        return error_result


        return error_result


# ─────────────────────────────────────────────────────────────
# Database-Driven Multi-Account Polling Daemon
# ─────────────────────────────────────────────────────────────

MOCK_EMAIL_TEMPLATES = [
    {
        "subject": "⚠️ URGENT: Your PayPal Account Has Been Suspended",
        "from": "security-alert@paypaI-verify.tk",
        "snippet": "Urgent: Your account has been compromised. Click here to verify.",
        "body_plain": "Dear Valued Customer, We have detected unusual activity on your PayPal account. Click here to verify: http://paypaI-secure-login.tk/verify?token=abc123&user=victim",
        "attachments": [{"filename": "account_verification_form.exe", "mimeType": "application/x-msdownload", "size": 102400}]
    },
    {
        "subject": "Microsoft 365: Password Expiration Notice",
        "from": "Office 365 Security <no-reply@office365-verify.com>",
        "snippet": "Your Microsoft 365 password expires in 2 hours. Update now.",
        "body_plain": "Dear Office 365 User, Please update your password immediately at: http://login.office365.com.phishing-portal.net/update-password to avoid losing access.",
        "attachments": []
    },
    {
        "subject": "Invoice #83726 Payment Received",
        "from": "Billing Dept <billing@invoicing-hub.net>",
        "snippet": "Attached is the invoice confirmation receipt for your payment.",
        "body_plain": "Thank you for your payment. Please view the attached invoice: invoice_receipt.pdf",
        "attachments": [{"filename": "invoice_receipt.pdf", "mimeType": "application/pdf", "size": 48200}]
    },
    {
        "subject": "Weekly Q2 Team Marketing Performance Review",
        "from": "Sarah Jenkins <sjenkins@company.com>",
        "snippet": "Hi team, here is the performance review document for this week.",
        "body_plain": "Hi team, please find the performance details for this week. No action needed.",
        "attachments": []
    },
    {
        "subject": "Flash Sale: 50% Off Cyber Security Training!",
        "from": "LearnSec News <newsletter@learn-security-marketing.com>",
        "snippet": "Don't miss our exclusive 50% discount on all cyber training courses.",
        "body_plain": "Hey there, subscribe now and get 50% off our courses! Click here to subscribe: http://learn-security-marketing.com/subscribe",
        "attachments": []
    }
]

def generate_mock_email(account_email: str, template: dict) -> dict:
    msg_id = f"mock_{str(uuid.uuid4())[:12]}"
    date_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    
    return {
        "id":           msg_id,
        "thread_id":    f"thread_{msg_id}",
        "snippet":      template["snippet"],
        "from":         template["from"],
        "to":           account_email,
        "subject":      template["subject"],
        "date":         date_str,
        "reply_to":     template["from"],
        "return_path":  template["from"],
        "received":     "from mail-server.net (192.0.2.1)",
        "body_plain":   template["body_plain"],
        "body_html":    f"<html><body><p>{template['body_plain']}</p></body></html>",
        "attachments":  template.get("attachments", []),
        "raw_headers":  {
            "from":         template["from"],
            "to":           account_email,
            "subject":      template["subject"],
        }
    }


def run_mail_monitoring_worker(gmail_service=None, outlook_service=None, source="both"):
    """
    Run continuous mail ingestion in a background thread.
    Reads accounts dynamically from SQLite and processes unread messages.
    """
    global MONITOR_ACTIVE
    if MONITOR_ACTIVE:
        logger.info("Background mail monitoring worker is already running.")
        return
    MONITOR_ACTIVE = True
    
    logger.info("Starting background mail monitoring worker...")
    
    import db_manager
    existing_accounts = db_manager.get_accounts()
    if not existing_accounts:
        db_manager.add_account("sec-analyst@enterprise.com", "mock")
        db_manager.add_account("finance@enterprise.com", "mock")
        existing_accounts = db_manager.get_accounts()

    with STATE_LOCK:
        PLAYBOOK_STATE.update({
            "running":     True,
            "stage":       "starting",
            "stages":      [],
            "result":      None,
            "error":       None,
            "queue_size":  0,
            "queue_index": 0,
            "mode":        "backfill",
            "source":      source,
            "started_at":  datetime.now(timezone.utc).isoformat(),
        })

    # Step 1: BACKFILL (Initial pull for all accounts)
    emails_to_process = []
    
    for account in existing_accounts:
        acc_id = account["id"]
        email = account["email"]
        provider = account["provider"]
        
        processed_ids = db_manager.load_processed_emails_for_account(acc_id)
        
        if provider == "mock":
            # Seed mock accounts with 4 initial emails if empty
            if not processed_ids:
                for idx in range(min(4, len(MOCK_EMAIL_TEMPLATES))):
                    template = MOCK_EMAIL_TEMPLATES[idx]
                    mock_mail = generate_mock_email(email, template)
                    emails_to_process.append((acc_id, provider, mock_mail))
        
        elif provider == "gmail":
            try:
                from gmail_connector import get_gmail_service
                service = get_gmail_service(email)
                if service:
                    result = service.users().messages().list(
                        userId="me",
                        labelIds=["INBOX"],
                        q="is:unread"
                    ).execute()
                    for m in result.get("messages", []):
                        msg_id = m["id"]
                        if msg_id not in processed_ids:
                            emails_to_process.append((acc_id, provider, msg_id))
            except Exception as e:
                logger.error(f"Gmail backfill error for {email}: {e}")
                
        elif provider == "outlook":
            try:
                from outlook_connector import fetch_unread_outlook_emails
                outlook_emails = fetch_unread_outlook_emails(email)
                for msg in outlook_emails:
                    msg_id = msg.get("id")
                    if msg_id and msg_id not in processed_ids:
                        emails_to_process.append((acc_id, provider, msg))
            except Exception as e:
                logger.error(f"Outlook backfill error for {email}: {e}")

    queue_size = len(emails_to_process)
    logger.info(f"Backfill stage: found {queue_size} emails to process across accounts.")
    
    with STATE_LOCK:
        PLAYBOOK_STATE["queue_size"] = queue_size

    # Process backfill queue
    for idx, item in enumerate(emails_to_process, 1):
        with STATE_LOCK:
            if not PLAYBOOK_STATE["running"]:
                break
            PLAYBOOK_STATE["queue_index"] = idx
            PLAYBOOK_STATE["stage"] = f"Processing backfill {idx}/{queue_size}"
            
        acc_id, provider, mail_data = item
        service_gmail = None
        
        try:
            if provider == "gmail":
                account_email = next(a["email"] for a in existing_accounts if a["id"] == acc_id)
                from gmail_connector import get_gmail_service, fetch_email_by_id
                service_gmail = get_gmail_service(account_email)
                parsed_email = fetch_email_by_id(service_gmail, mail_data)
                msg_id = mail_data
            elif provider == "outlook":
                parsed_email = mail_data
                msg_id = parsed_email.get("id")
            else:  # mock
                parsed_email = mail_data
                msg_id = parsed_email.get("id")
                
            if parsed_email:
                logger.info(f"Ingestion Queue: Processing email {idx}/{queue_size} from account {acc_id} - ID: {msg_id}")
                
                result = run_playbook(
                    email_data=parsed_email,
                    gmail_service=service_gmail,
                    outlook_service=outlook_service if provider == "outlook" else None,
                    is_queue_run=True
                )
                
                db_manager.save_email(
                    email_data=parsed_email,
                    account_id=acc_id,
                    verdict=result.get("verdict", "CLEAN"),
                    score=result.get("score", 0),
                    ticket_id=result.get("ticket_id", ""),
                    gemma_advisory=result.get("gemma_advisory", "")
                )
                
                with STATE_LOCK:
                    PLAYBOOK_STATE["result"] = result
            
            time.sleep(1.5)
        except Exception as e:
            logger.error(f"Error processing email {idx} in backfill queue: {e}")

    # Transition to continuous POLLING stage
    logger.info("Transitioning to continuous multi-account polling stage...")
    with STATE_LOCK:
        PLAYBOOK_STATE["mode"] = "monitoring"
        PLAYBOOK_STATE["stage"] = "monitoring"
        PLAYBOOK_STATE["queue_size"] = 0
        PLAYBOOK_STATE["queue_index"] = 0
        PLAYBOOK_STATE["running"] = False

    try:
        while True:
            if not MONITOR_ACTIVE:
                break
                
            active_accounts = db_manager.get_accounts()
            new_emails = []
            
            for account in active_accounts:
                acc_id = account["id"]
                email = account["email"]
                provider = account["provider"]
                
                processed_ids = db_manager.load_processed_emails_for_account(acc_id)
                
                if provider == "mock":
                    # If mock account has no emails, seed initial ones immediately
                    if not processed_ids:
                        logger.info(f"Seeding new mock account {email} with initial emails...")
                        for idx in range(min(4, len(MOCK_EMAIL_TEMPLATES))):
                            template = MOCK_EMAIL_TEMPLATES[idx]
                            mock_mail = generate_mock_email(email, template)
                            new_emails.append((acc_id, provider, mock_mail))
                    # 20% chance of receiving a new mock email each poll cycle
                    elif random.random() < 0.20:
                        template = random.choice(MOCK_EMAIL_TEMPLATES)
                        mock_mail = generate_mock_email(email, template)
                        if mock_mail["id"] not in processed_ids:
                            new_emails.append((acc_id, provider, mock_mail))
                            
                elif provider == "gmail":
                    try:
                        from gmail_connector import get_gmail_service
                        service_gmail = get_gmail_service(email)
                        if service_gmail:
                            result = service_gmail.users().messages().list(
                                userId="me",
                                labelIds=["INBOX"],
                                q="is:unread"
                            ).execute()
                            for m in result.get("messages", []):
                                msg_id = m["id"]
                                if msg_id not in processed_ids:
                                    new_emails.append((acc_id, provider, msg_id))
                    except Exception as e:
                        logger.error(f"Gmail poll error for {email}: {e}")
                        
                elif provider == "outlook":
                    try:
                        from outlook_connector import fetch_unread_outlook_emails
                        outlook_emails = fetch_unread_outlook_emails(email)
                        for msg in outlook_emails:
                            msg_id = msg.get("id")
                            if msg_id and msg_id not in processed_ids:
                                new_emails.append((acc_id, provider, msg))
                    except Exception as e:
                        logger.error(f"Outlook poll error for {email}: {e}")

            if new_emails:
                logger.info(f"Polling: detected {len(new_emails)} new email(s) across accounts. Processing...")
                for idx, item in enumerate(new_emails, 1):
                    if not MONITOR_ACTIVE:
                        break
                    
                    acc_id, provider, mail_data = item
                    service_gmail = None
                    
                    try:
                        if provider == "gmail":
                            account_email = next(a["email"] for a in active_accounts if a["id"] == acc_id)
                            from gmail_connector import get_gmail_service, fetch_email_by_id
                            service_gmail = get_gmail_service(account_email)
                            parsed_email = fetch_email_by_id(service_gmail, mail_data)
                            msg_id = mail_data
                        elif provider == "outlook":
                            parsed_email = mail_data
                            msg_id = parsed_email.get("id")
                        else:  # mock
                            parsed_email = mail_data
                            msg_id = parsed_email.get("id")

                        if parsed_email:
                            logger.info(f"Ingestion Polling: Processing incoming email {msg_id} for {acc_id}")
                            result = run_playbook(
                                email_data=parsed_email,
                                gmail_service=service_gmail,
                                outlook_service=outlook_service if provider == "outlook" else None,
                                is_queue_run=False
                            )
                            
                            db_manager.save_email(
                                email_data=parsed_email,
                                account_id=acc_id,
                                verdict=result.get("verdict", "CLEAN"),
                                score=result.get("score", 0),
                                ticket_id=result.get("ticket_id", ""),
                                gemma_advisory=result.get("gemma_advisory", "")
                            )
                            
                            with STATE_LOCK:
                                PLAYBOOK_STATE["result"] = result
                    except Exception as e:
                        logger.error(f"Error processing new polled email: {e}")
                
                with STATE_LOCK:
                    PLAYBOOK_STATE["stage"] = "monitoring"
                        
            time.sleep(10)
    finally:
        MONITOR_ACTIVE = False
        logger.info("Background mail monitoring worker terminated.")
        with STATE_LOCK:
            PLAYBOOK_STATE["stage"] = "idle"


# ─────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SOAR Phishing Response Playbook",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo             # Run with built-in phishing demo email
  python main.py                    # Process latest Gmail inbox email
  python main.py --email-id MSG_ID  # Process specific Gmail message
        """
    )
    parser.add_argument("--demo",     action="store_true", help="Use demo phishing email")
    parser.add_argument("--email-id", type=str,            help="Gmail message ID to process")
    parser.add_argument("--no-gmail", action="store_true", help="Skip Gmail auth (use with --demo)")
    args = parser.parse_args()

    gmail_service = None
    if not args.demo and not args.no_gmail:
        try:
            from gmail_connector import get_gmail_service
            gmail_service = get_gmail_service()
        except Exception as e:
            logger.warning(f"Could not connect to Gmail: {e}")
            logger.info("Tip: Use --demo flag to run without Gmail")

    result = run_playbook(
        gmail_service=gmail_service,
        email_id=args.email_id,
        use_demo=args.demo or gmail_service is None,
    )

    print(f"\n{'='*60}")
    print(f"[DONE] Completed in {result.get('elapsed_sec', 0)}s")
    print(f"[VERDICT] {result.get('verdict', 'N/A')}")
    print(f"[TICKET] {result.get('ticket_id', 'N/A')}")
    if result.get("html_path"):
        print(f"[REPORT] {result['html_path']}")
    print(f"{'='*60}\n")
