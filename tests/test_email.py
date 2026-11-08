"""
Check that MalSense can send email through Gmail.
Usage (inside the .venv):   python tests/test_email.py you@example.com
Prints exactly what went wrong if sending fails.
"""
import os, sys, smtplib, socket
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
user = os.getenv("MAIL_USERNAME")
password = (os.getenv("MAIL_PASSWORD") or "").replace(" ", "")
to = sys.argv[1] if len(sys.argv) > 1 else user
print(f"MAIL_USERNAME: {user or 'MISSING'}   MAIL_PASSWORD: {'set (' + str(len(password)) + ' chars)' if password else 'MISSING'}")
if not user or not password:
    sys.exit("-> Add MAIL_USERNAME and MAIL_PASSWORD to .env")

msg = EmailMessage()
msg["Subject"], msg["From"], msg["To"] = "MalSense test email", f"MalSense <{user}>", to
msg.set_content("If you can read this, MalSense can send email.")
try:
    print("Connecting to smtp.gmail.com:465 ...")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as s:
        s.login(user, password)
        s.send_message(msg)
    print(f"SENT to {to} - check the inbox and the Spam folder.")
except smtplib.SMTPAuthenticationError as e:
    print("LOGIN REFUSED by Gmail:", e.smtp_error.decode(errors="ignore")[:200])
    print("-> Make a NEW App Password at myaccount.google.com/apppasswords (2-Step Verification must be ON),")
    print("   paste it into MAIL_PASSWORD, save .env and restart python app.py")
except (socket.timeout, TimeoutError, ConnectionError, OSError) as e:
    print("CONNECTION PROBLEM:", e)
    print("-> Your network or antivirus/firewall is blocking port 465. Try another network (e.g. phone hotspot),")
    print("   or allow Python through the firewall.")
