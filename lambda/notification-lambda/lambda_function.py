import json
import logging
import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _parse_recipients(raw_value):
    if not raw_value:
        return []
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def _build_email_subject(dry_run, run_id):
    mode = "DRY RUN" if dry_run else "DELETION"
    return f"[Cleanup Automation] Prior Intimation - {mode} - {run_id}"


def _build_email_body(event_input, run_id, attempt):
    regions = event_input.get("regions", [])
    dry_run = event_input.get("dryRun", event_input.get("dry_run", True))
    exclusions = event_input.get("exclusions", {})
    now_utc = datetime.now(timezone.utc).isoformat()

    lines = [
        "This is a prior intimation for the scheduled AWS cleanup activity.",
        "",
        f"Timestamp (UTC): {now_utc}",
        f"Execution ID: {run_id}",
        f"Attempt: {attempt}",
        f"Dry Run: {dry_run}",
        f"Regions: {', '.join(regions) if regions else 'N/A'}",
        "",
        "Exclusions:",
        json.dumps(exclusions, indent=2),
        "",
        "This mail was sent by the Cleanup Automation notification Lambda.",
    ]
    return "\n".join(lines)


def _send_mail(subject, body_text):
    smtp_host = os.environ.get("SMTP_HOST", "test.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "425"))
    smtp_use_starttls = _parse_bool(os.environ.get("SMTP_USE_STARTTLS"), default=False)
    smtp_username = os.environ.get("SMTP_USERNAME", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "")
    mail_from = os.environ.get("MAIL_FROM", "cleanup-automation@test.com").strip()
    mail_to_raw = os.environ.get("MAIL_TO", "").strip()
    recipients = _parse_recipients(mail_to_raw)

    if not recipients:
        raise ValueError("MAIL_TO must contain at least one recipient email address")

    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(body_text)

    logger.info("Sending prior intimation mail via %s:%s to %s", smtp_host, smtp_port, recipients)

    with smtplib.SMTP(host=smtp_host, port=smtp_port, timeout=30) as smtp:
        smtp.ehlo()
        if smtp_use_starttls:
            smtp.starttls()
            smtp.ehlo()
        if smtp_username:
            smtp.login(smtp_username, smtp_password)
        smtp.send_message(msg)


def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    run_id = event.get("runId", "N/A")
    attempt = event.get("attempt", 1)
    event_input = event.get("input", {})
    dry_run = event_input.get("dryRun", event_input.get("dry_run", True))

    subject = _build_email_subject(dry_run=dry_run, run_id=run_id)
    body = _build_email_body(event_input=event_input, run_id=run_id, attempt=attempt)

    _send_mail(subject=subject, body_text=body)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Prior intimation mail sent",
                "runId": run_id,
                "attempt": attempt,
            }
        ),
    }
