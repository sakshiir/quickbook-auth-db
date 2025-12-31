import os
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import requests

from dotenv import load_dotenv
from flask import Flask, request, redirect, url_for, jsonify, render_template_string, session
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
from werkzeug.middleware.proxy_fix import ProxyFix

import psycopg2
import psycopg2.extras

# ------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------
load_dotenv()
PG_DB_URL = os.environ.get("PG_DB_URL")

APP = Flask(__name__)
# Use a consistent secret key for production to keep sessions valid across restarts
APP.secret_key = os.getenv("FLASK_SECRET_KEY", "prod-session-secret-9911")

# Tell Flask it's behind Nginx (fixes MismatchingStateError)
APP.wsgi_app = ProxyFix(APP.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

APP.config.update(
    SESSION_COOKIE_SECURE=True,    # Required for HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax', # Crucial for OAuth redirects
    PERMANENT_SESSION_LIFETIME=timedelta(days=90)
)

CLIENT_ID = os.getenv("INTUIT_CLIENT_ID")
CLIENT_SECRET = os.getenv("INTUIT_CLIENT_SECRET")
REDIRECT_URI = os.getenv("INTUIT_REDIRECT_URI")
QBO_ENV = (os.getenv("QBO_ENV", "sandbox") or "sandbox").lower()

CONF_URL = 'https://developer.api.intuit.com/.well-known/openid_configuration/'
AUTH_URL = "https://appcenter.intuit.com/connect/oauth2"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
USERINFO_URL = "https://accounts.platform.intuit.com/v1/openid_connect/userinfo"

API_BASE = "https://sandbox-quickbooks.api.intuit.com" if QBO_ENV == "sandbox" else "https://quickbooks.api.intuit.com"
SCOPE = "com.intuit.quickbooks.accounting openid email profile"

# ------------------------------------------------------------------
# OAuth client
# ------------------------------------------------------------------
oauth = OAuth(APP)

intuit = oauth.register(
    name="intuit",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    authorize_url=AUTH_URL,
    access_token_url=TOKEN_URL,
    api_base_url=API_BASE,
    client_kwargs={"scope": SCOPE}

    #server_metadata_url=CONF_URL, 
    # Setting this to True allows Authlib to manage the nonce in the session automatically
    #id_token_params={"nonce": None, "validate_nonce": False}
)

# ------------------------------------------------------------------
# Database connections
# ------------------------------------------------------------------
def get_db_conn():
    if not PG_DB_URL:
        raise ValueError("PG_DB_URL environment variable not set.")
    return psycopg2.connect(PG_DB_URL)

def upsert_qbo_token(token: dict, realm_id: str, intuit_email: str = None, intuit_user_id: str = None):
    conn = None
    cur = None
    try: 
        conn = get_db_conn()
        cur = conn.cursor()

        issued_at = datetime.now(timezone.utc)
        expires_in = token.get("expires_in")
        access_expiry = issued_at.timestamp() + expires_in if expires_in else None
        
        refresh_expires_in = token.get("x_refresh_token_expires_in")
        refresh_expiry = issued_at.timestamp() + refresh_expires_in if refresh_expires_in else None

        cur.execute(
            """
            INSERT INTO config.qbo_oauth_tokens (
                realm_id, intuit_user_id,intuit_email, access_token, refresh_token,
                token_type, expires_in, refresh_expires_in, issued_at_utc,
                access_token_expires_at, refresh_token_expires_at,
                qbo_environment, client_id, created_at, updated_at
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,to_timestamp(%s),to_timestamp(%s),%s,%s,now(),now())
            ON CONFLICT (realm_id, qbo_environment)
            DO UPDATE SET
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                expires_in = EXCLUDED.expires_in,
                refresh_expires_in = EXCLUDED.refresh_expires_in,
                issued_at_utc = EXCLUDED.issued_at_utc,
                access_token_expires_at = EXCLUDED.access_token_expires_at,
                refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
                intuit_user_id = EXCLUDED.intuit_user_id,
                intuit_email = EXCLUDED.intuit_email,
                updated_at = now();
            """,
            (
                realm_id, intuit_email, token.get("access_token"),
                token.get("refresh_token"), token.get("token_type", "bearer"),
                expires_in, refresh_expires_in, issued_at,
                access_expiry, refresh_expiry, QBO_ENV, CLIENT_ID,
            ),
        )
        conn.commit()
    except Exception as e:
        print(f"PROD ERROR: Database upsert failed: {e}")
        if conn: conn.rollback()
    finally:
        if cur: cur.close()
        if conn: conn.close()


# ------------------------------------------------------------------
# UI
# ------------------------------------------------------------------
HOME = """
<!doctype html>
<html>
  <body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
    <h1>QBO OAuth → PostgreSQL</h1>
    <p>
      <a href="{{ url_for('start') }}"
         style="padding:10px 14px;background:#111;color:#fff;text-decoration:none;border-radius:6px;">
         Authenticate in Browser
      </a>
    </p>
    <p>
      <a href="{{ url_for('peek') }}">Peek (DB)</a>
    </p>
    <hr/>
    <p>Redirect URI must match: <code>{{ redirect_uri }}</code></p>
  </body>
</html>
"""


@APP.route("/")
def home():
    return render_template_string(HOME, redirect_uri=REDIRECT_URI)

# ------------------------------------------------------------------
# OAuth flow
# ------------------------------------------------------------------
@APP.route("/start")
def start():
    # nonce = generate_token()
    # session['nonce'] = nonce
    # print(f"DEBUG: Redirecting with nonce: {nonce}")
    # return intuit.authorize_redirect(REDIRECT_URI, nonce=nonce, prompt="consent")
    session.permanent = True # Authlib handles the nonce generation/storage automatically here
    return intuit.authorize_redirect(REDIRECT_URI, prompt="consent")

@APP.route("/callback")
def callback():
    code = request.args.get("code")
    realm_id = request.args.get("realmId")

    if not code or not realm_id:
        return "Missing authorization code or realmId", 400

    try:
        # 1. Exchange code for token
        response = requests.post(
            TOKEN_URL,
            auth=(CLIENT_ID, CLIENT_SECRET),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
            timeout=10
        )
        response.raise_for_status()

        token = response.json()
        access_token = token.get("access_token")

        if not access_token:
            return "Access token missing in response", 400

        # 2. Fetch email from UserInfo
        intuit_email = None
        r = requests.get(
            USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10
        )
        if r.status_code == 200:
            intuit_email = r.json().get("email")
            intuit_user_id = r.json().get("sub")

        # 3. Persist
        upsert_qbo_token(token, realm_id, intuit_email,intuit_user_id)

        return redirect(url_for("peek"))

    except requests.RequestException as e:
        print(f"HTTP error during OAuth callback: {e}")
        return "OAuth communication failed", 502

    except Exception as e:
        print(f"Unexpected OAuth callback error: {e}")
        return "Authentication failed", 500


# ------------------------------------------------------------------
# Peek from database
# ------------------------------------------------------------------
@APP.route("/peek")
def peek():
    conn = get_db_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT realm_id, intuit_email, qbo_environment, refresh_token_expires_at FROM config.qbo_oauth_tokens ORDER BY updated_at DESC LIMIT 5;")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=5000)