"""
Feedback / enquiry form: messages are emailed to the MalSense owner.
The owner's address is only kept on the server (FEEDBACK_TO in .env) - it is never shown on the website.
"""
import os
from datetime import datetime
from html import escape

import account_security as sec

TOPICS = [
    ("question", "Question or enquiry"),
    ("complaint", "Complaint"),
    ("bug", "Something is not working"),
    ("privacy", "My data / privacy request (see, correct or delete)"),
    ("suggestion", "Suggestion"),
]
TOPIC_LABEL = dict(TOPICS)
MAX_MESSAGE = 3000


def recipient():
    return (os.getenv("FEEDBACK_TO") or "").strip()


def send(name, email, topic, message, account=None, logger=None):
    """Email one feedback message to the owner. Returns True if it was sent."""
    to = recipient()
    if not to:                                           # no address in .env: do not send, tell the log
        if logger:
            logger.error("FEEDBACK_TO is not set in .env - feedback email not sent")
        return False
    label = TOPIC_LABEL.get(topic, "Feedback")
    when = datetime.now().strftime("%d %b %Y, %H:%M")
    who = f"{name or '(no name)'} <{email}>"
    acct = f"Registered user #{account.user_id} ({account.email})" if account else "Not logged in"
    text = (f"New MalSense feedback\n\nTopic: {label}\nFrom: {who}\nAccount: {acct}\nSent: {when}\n\n"
            f"{message}\n\n-- Reply to this email to answer {email} directly.")
    rows = "".join(f'<tr><td style="color:#9aa0b8;padding:4px 14px 4px 0">{k}</td><td>{escape(v)}</td></tr>'
                   for k, v in (("Topic", label), ("From", who), ("Account", acct), ("Sent", when)))
    html = (f'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:600px;margin:auto;padding:24px;'
            f'background:#12101e;color:#eef0f8;border-radius:6px">'
            f'<h2 style="margin:0 0 14px">Mal<span style="color:#3d8bfd">Sense</span> feedback</h2>'
            f'<table style="font-size:14px;margin-bottom:16px">{rows}</table>'
            f'<div style="white-space:pre-wrap;line-height:1.6;background:#1c1930;padding:14px 16px;border-radius:4px">'
            f'{escape(message)}</div>'
            f'<p style="color:#9aa0b8;font-size:13px">Reply to this email to answer {escape(email)} directly.</p></div>')
    return sec.send_email(to, f"[MalSense feedback] {label}", text, html, logger=logger, reply_to=email)
