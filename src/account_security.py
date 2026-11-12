"""
Account security for MalSense: real-email checks, email verification and password reset.

1. Email checks at registration
   - the domain must be able to receive email (it has MX/DNS records) -> catches typos and made-up domains
   - throwaway "disposable" email services are refused
2. Email verification - a signed link (itsdangerous, signed with FLASK_SECRET_KEY) that expires after 24 hours.
   An account cannot log in until the link is clicked.
3. Password reset - a signed link that expires after 30 minutes and works only ONCE
   (it contains part of the current password hash, so it stops working as soon as the password changes).

Email is sent through Gmail SMTP. Settings in .env:
    MAIL_USERNAME=malsense.noreply@gmail.com
    MAIL_PASSWORD=<16-character Gmail App Password>
If they are missing, the link is printed in the terminal instead (useful for testing).
"""
import os
import smtplib
import socket
from email.message import EmailMessage

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

VERIFY_MAX_AGE = 24 * 3600          # verification link: 24 hours
RESET_MAX_AGE = 30 * 60             # password-reset link: 30 minutes

# Common throwaway email services (not complete, but stops the obvious ones)
DISPOSABLE = {
    "mailinator.com", "10minutemail.com", "10minutemail.net", "guerrillamail.com", "guerrillamail.net",
    "sharklasers.com", "grr.la", "yopmail.com", "yopmail.net", "tempmail.com", "temp-mail.org", "temp-mail.io",
    "tempmailo.com", "throwawaymail.com", "trashmail.com", "getnada.com", "nada.email", "dispostable.com",
    "maildrop.cc", "mintemail.com", "mohmal.com", "emailondeck.com", "fakeinbox.com", "mailnesia.com",
    "mailcatch.com", "spamgourmet.com", "tempinbox.com", "moakt.com", "burnermail.io", "tmpmail.org",
    "tmpmail.net", "emailfake.com", "fakemail.net", "inboxkitten.com", "mail.tm", "mailpoof.com", "trbvm.com",
    "1secmail.com", "1secmail.net", "1secmail.org", "byom.de", "spambox.us", "getairmail.com", "anonaddy.me",
}


# ----------------------------------------------------------------------------- 1. email checks
def domain_accepts_mail(domain):
    """True if the domain has mail (MX) records - or, if dnspython is not installed, at least exists in DNS."""
    try:
        import dns.resolver                                   # pip install dnspython
        try:
            return len(dns.resolver.resolve(domain, "MX", lifetime=5)) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return False
        except dns.exception.Timeout:
            return True                                       # no internet / slow DNS: do not block the user
    except ImportError:
        try:
            socket.getaddrinfo(domain, None)
            return True
        except socket.gaierror:
            return False


def email_problem(email):
    """None if the email looks real, otherwise a message for the user."""
    domain = email.rsplit("@", 1)[-1].lower()
    if domain in DISPOSABLE or any(domain.endswith("." + d) for d in DISPOSABLE):
        return "Disposable (temporary) email addresses are not allowed. Please use your real email."
    # if even gmail.com cannot be looked up, the server is offline - then do not block anyone
    if not domain_accepts_mail(domain) and domain_accepts_mail("gmail.com"):
        return f"The email domain \"{domain}\" cannot receive email. Please check for typos."
    return None


# ----------------------------------------------------------------------------- 2./3. signed links
def _serializer(secret, salt):
    return URLSafeTimedSerializer(secret, salt=salt)


def make_verify_token(secret, user):
    return _serializer(secret, "verify-email").dumps({"id": user.user_id, "email": user.email})


def read_verify_token(secret, token):
    """Returns (data, error). error is 'expired' or 'invalid'."""
    try:
        return _serializer(secret, "verify-email").loads(token, max_age=VERIFY_MAX_AGE), None
    except SignatureExpired:
        return None, "expired"
    except BadSignature:
        return None, "invalid"


def make_reset_token(secret, user):
    return _serializer(secret, "reset-password").dumps({"id": user.user_id, "pw": user.password_hash[-12:]})


def read_reset_token(secret, token):
    try:
        return _serializer(secret, "reset-password").loads(token, max_age=RESET_MAX_AGE), None
    except SignatureExpired:
        return None, "expired"
    except BadSignature:
        return None, "invalid"


# ----------------------------------------------------------------------------- sending email
def send_email(to, subject, text, html, logger=None, reply_to=None):
    """Send one email (provider chosen by MAIL_PROVIDER: smtp / gmail_api / brevo). Returns True if sent.
    Render's free plan blocks SMTP ports, so online MalSense uses gmail_api (HTTPS).
    Without settings, prints the email instead."""
    provider = (os.getenv("MAIL_PROVIDER") or "smtp").strip().lower()
    user = os.getenv("MAIL_USERNAME")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, f"MalSense <{user}>", to
    if reply_to:                                         # feedback form: "Reply" goes to the visitor
        msg["Reply-To"] = reply_to
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    try:
        if provider == "gmail_api":
            return _send_gmail_api(msg, to, subject, text)
        if provider == "brevo":
            return _send_brevo(user, to, subject, text, html, reply_to)
        return _send_smtp(msg, user, to, subject, text)
    except Exception as e:
        if logger:
            logger.error(f"Could not send email to {to} ({provider}): {e}")
        return False


def _print_instead(missing, to, subject, text):
    print(f"\n[MalSense mail - not sent, {missing} missing]\nTo: {to}\nSubject: {subject}\n{text}\n", flush=True)
    return False


def _send_smtp(msg, user, to, subject, text):
    password = (os.getenv("MAIL_PASSWORD") or "").replace(" ", "")
    if not user or not password:
        return _print_instead("MAIL_USERNAME/MAIL_PASSWORD", to, subject, text)
    with smtplib.SMTP_SSL(os.getenv("MAIL_SERVER", "smtp.gmail.com"), int(os.getenv("MAIL_PORT", 465)),
                          timeout=20) as s:
        s.login(user, password)
        s.send_message(msg)
    return True


def _send_gmail_api(msg, to, subject, text):
    """Gmail API over HTTPS (port 443): swap the long-lived refresh token for a short access token, then send."""
    import base64
    import requests
    cid, secret, refresh = (os.getenv("GMAIL_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID"),
                            os.getenv("GMAIL_CLIENT_SECRET") or os.getenv("GOOGLE_CLIENT_SECRET"),
                            os.getenv("GMAIL_REFRESH_TOKEN"))
    if not (cid and secret and refresh):
        return _print_instead("GMAIL_REFRESH_TOKEN / client id / client secret", to, subject, text)
    tok = requests.post("https://oauth2.googleapis.com/token", timeout=20,
                        data={"client_id": cid, "client_secret": secret, "refresh_token": refresh,
                              "grant_type": "refresh_token"})
    tok.raise_for_status()
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    r = requests.post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", timeout=20,
                      headers={"Authorization": f"Bearer {tok.json()['access_token']}"}, json={"raw": raw})
    if r.status_code != 200:
        raise RuntimeError(f"Gmail API HTTP {r.status_code}: {r.text[:200]}")
    return True


def _send_brevo(user, to, subject, text, html, reply_to):
    import requests
    key = os.getenv("BREVO_API_KEY")
    if not (user and key):
        return _print_instead("MAIL_USERNAME/BREVO_API_KEY", to, subject, text)
    body = {"sender": {"name": "MalSense", "email": user}, "to": [{"email": to}],
            "subject": subject, "htmlContent": html, "textContent": text}
    if reply_to:
        body["replyTo"] = {"email": reply_to}
    r = requests.post("https://api.brevo.com/v3/smtp/email", json=body, timeout=20,
                      headers={"api-key": key, "accept": "application/json"})
    if r.status_code not in (200, 201, 202):
        raise RuntimeError(f"Brevo HTTP {r.status_code}: {r.text[:200]}")
    return True


def _html(title, intro, button, link, note):
    return f"""<div style="font-family:Segoe UI,Arial,sans-serif;max-width:520px;margin:auto;padding:24px;
background:#12101e;color:#eef0f8;border-radius:6px">
<h2 style="margin:0 0 4px;color:#fff">Mal<span style="color:#3d8bfd">Sense</span></h2>
<h3 style="margin:18px 0 8px;color:#fff">{title}</h3>
<p style="color:#c9cbe0;line-height:1.5">{intro}</p>
<p style="margin:26px 0"><a href="{link}" style="background:#ff2fd6;color:#160016;padding:12px 26px;
text-decoration:none;font-weight:bold;border-radius:3px">{button}</a></p>
<p style="color:#9aa0b8;font-size:13px;line-height:1.5">{note}<br>If the button does not work, copy this link:<br>
<span style="color:#1de9ff;word-break:break-all">{link}</span></p></div>"""


def send_verification(user, link, logger=None):
    intro = (f"Hello {user.username.split()[0]}, thank you for registering. "
             "Please confirm that this email address belongs to you.")
    note = "This link expires in 24 hours. If you did not create a MalSense account, you can ignore this email."
    return send_email(user.email, "Verify your MalSense account",
                      f"{intro}\n\nOpen this link to verify your account:\n{link}\n\n{note}",
                      _html("Verify your email", intro, "Verify my email", link, note), logger)


def send_reset(user, link, logger=None):
    intro = (f"Assalamualaikum {user.username.split()[0]}, we received a request to reset your MalSense password.")
    note = ("This link expires in 30 minutes and can be used once. If you did not ask for this, ignore this "
            "email - your password stays the same.")
    return send_email(user.email, "Reset your MalSense password",
                      f"{intro}\n\nOpen this link to choose a new password:\n{link}\n\n{note}",
                      _html("Reset your password", intro, "Choose a new password", link, note), logger)
