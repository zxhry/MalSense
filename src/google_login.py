"""
"Continue with Google" sign-in (OAuth 2.0 / OpenID Connect, authorisation-code flow with PKCE).
Uses only `requests` (already installed) - no extra package needed.

How it works:
  1. start()  -> MalSense sends the user to Google's sign-in page, with a random `state` (stops forged
                 replies / CSRF) and a PKCE `code_challenge` (stops a stolen code from being reused).
  2. Google sends the user back to /auth/google/callback?code=...&state=...
  3. finish() -> MalSense swaps the code for a token directly with Google (server-to-server, over HTTPS),
                 then asks Google who the user is (name, email, whether the email is verified).
MalSense never sees the user's Google password.

Needs two values in .env (from Google Cloud Console > APIs & Services > Credentials):
  GOOGLE_CLIENT_ID=...apps.googleusercontent.com
  GOOGLE_CLIENT_SECRET=...
Optional: GOOGLE_REDIRECT_URI (default: this site's /auth/google/callback address).
"""
import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

import requests

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"


class GoogleLoginError(Exception):
    """Anything that went wrong while talking to Google."""


def configured():
    return bool(os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"))


def redirect_uri(default):
    return os.getenv("GOOGLE_REDIRECT_URI") or default


def start(callback_url):
    """Returns (google_url, state, code_verifier). Keep state + verifier in the session."""
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "redirect_uri": callback_url,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",            # always let the user pick which Google account
    }
    return f"{AUTH_URL}?{urlencode(params)}", state, verifier


def finish(code, verifier, callback_url):
    """Swap the one-time code for a token, then return Google's user info:
    {'sub', 'email', 'email_verified', 'name', 'picture', ...}"""
    if not code:
        raise GoogleLoginError("no code from Google")
    try:
        tok = requests.post(TOKEN_URL, timeout=10, data={
            "code": code,
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "redirect_uri": callback_url,
            "grant_type": "authorization_code",
            "code_verifier": verifier,
        })
        if tok.status_code != 200:
            raise GoogleLoginError(f"token request failed: HTTP {tok.status_code} {tok.text[:200]}")
        access = tok.json().get("access_token")
        if not access:
            raise GoogleLoginError("no access token in Google's reply")
        info = requests.get(USERINFO_URL, timeout=10, headers={"Authorization": f"Bearer {access}"})
        if info.status_code != 200:
            raise GoogleLoginError(f"user-info request failed: HTTP {info.status_code}")
        return info.json()
    except requests.RequestException as e:
        raise GoogleLoginError(f"network problem: {e}") from e
