"""
Run MalSense for OTHER people, through an ngrok tunnel (temporary public link).

    Terminal 1:  python run_public.py
    Terminal 2:  ngrok http --url=YOUR-DOMAIN.ngrok-free.app 5000

Differences from `python app.py` (which stays for working on your own laptop):
  - debug mode is OFF  (Flask's debug page must never be reachable from the internet -
                        it can let a visitor run commands on this computer)
  - ProxyFix: MalSense trusts ngrok's X-Forwarded-* headers, so links it makes
    (Google sign-in, email verification, password reset) use https://YOUR-DOMAIN, not 127.0.0.1
  - login cookies are only sent over HTTPS
"""
import os
from werkzeug.middleware.proxy_fix import ProxyFix
from app import app

if app.config.get("SECRET_KEY") in (None, "", "dev-only-change-me"):
    raise SystemExit("Set a long random FLASK_SECRET_KEY in .env before going public.")

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)   # exactly one proxy in front: ngrok
app.config.update(SESSION_COOKIE_SECURE=True, REMEMBER_COOKIE_SECURE=True, PREFERRED_URL_SCHEME="https")

if __name__ == "__main__":
    print("MalSense (public mode) on http://127.0.0.1:5000 - share it with:  ngrok http --url=YOUR-DOMAIN 5000")
    try:
        from waitress import serve                       # sturdier server, if installed (pip install waitress)
        serve(app, host="127.0.0.1", port=5000, threads=8)
    except ImportError:
        app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
