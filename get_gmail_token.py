"""
Run ONCE on your laptop to get the GMAIL_REFRESH_TOKEN that lets online MalSense send email
through the Gmail API (Render's free plan blocks normal SMTP email).

Before running (Google Cloud Console, same project as "Continue with Google"):
  1. APIs & Services > Library > enable "Gmail API".
  2. Credentials > your OAuth client > Authorized redirect URIs > add  http://127.0.0.1:8765/
  3. OAuth consent screen: set Publishing status to "In production"
     (in "Testing" the refresh token stops working after 7 days).

Then:  python get_gmail_token.py
Sign in with the Gmail account MalSense sends from (MAIL_USERNAME), allow "Send email",
and copy the printed GMAIL_REFRESH_TOKEN into Render's environment variables.
"""
import os, secrets, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from dotenv import load_dotenv

load_dotenv()
CLIENT_ID = os.getenv("GMAIL_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET") or os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT = "http://127.0.0.1:8765/"
STATE = secrets.token_urlsafe(16)
result = {}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        if q.get("state", [""])[0] == STATE and "code" in q:
            result["code"] = q["code"][0]
            msg = "Done - you can close this tab and go back to the terminal."
        else:
            result["error"] = q.get("error", ["unknown"])[0]
            msg = "Something went wrong - check the terminal."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(msg.encode())

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    if not (CLIENT_ID and CLIENT_SECRET):
        raise SystemExit("GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are missing in .env")
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
        "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "response_type": "code",
        "scope": "https://www.googleapis.com/auth/gmail.send",
        "access_type": "offline", "prompt": "consent", "state": STATE})
    print("Opening Google sign-in in your browser. If it does not open, visit:\n" + url)
    webbrowser.open(url)
    HTTPServer(("127.0.0.1", 8765), Handler).handle_request()      # wait for Google to redirect back
    if "code" not in result:
        raise SystemExit(f"Google sign-in failed: {result.get('error')}")
    r = requests.post("https://oauth2.googleapis.com/token", timeout=20, data={
        "code": result["code"], "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT, "grant_type": "authorization_code"})
    r.raise_for_status()
    token = r.json().get("refresh_token")
    if not token:
        raise SystemExit("Google did not return a refresh token - remove MalSense's access at "
                         "myaccount.google.com/permissions and run this again.")
    print("\nAdd this to Render > Environment (keep it secret):\n\nGMAIL_REFRESH_TOKEN=" + token + "\n")
