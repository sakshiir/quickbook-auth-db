import os
import json
from datetime import datetime, timezone
from pathlib import Path
import requests
from authlib.common.security import generate_token

from dotenv import load_dotenv
from flask import Flask, request, redirect, url_for, jsonify, render_template_string, session
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
import psycopg2.extensions
import psycopg2
import jwt

# ------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------
load_dotenv()
PG_DB_URL = os.environ.get("PG_DB_URL")

APP = Flask(__name__)
APP.secret_key = os.urandom(32)
APP.wsgi_app = ProxyFix(APP.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

APP.config.update(
    SESSION_COOKIE_SECURE=True,    # Required because you are using HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax', # Crucial for OAuth redirects
)

CLIENT_ID = os.getenv("INTUIT_CLIENT_ID")
CLIENT_SECRET = os.getenv("INTUIT_CLIENT_SECRET")
REDIRECT_URI = os.getenv("INTUIT_REDIRECT_URI")
QBO_ENV = (os.getenv("QBO_ENV", "sandbox") or "sandbox").lower()

AUTH_URL = "https://appcenter.intuit.com/connect/oauth2"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
USERINFO_URL = "https://accounts.platform.intuit.com/v1/openid_connect/userinfo"

API_BASE = (
    "https://sandbox-quickbooks.api.intuit.com"
    if QBO_ENV == "sandbox"
    else "https://quickbooks.api.intuit.com"
)

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
    client_kwargs={"scope": SCOPE},
)

# ------------------------------------------------------------------
# Database connections
# ------------------------------------------------------------------
if PG_DB_URL:
    engine = create_engine(PG_DB_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db_conn() -> Session:
    if SessionLocal is None:
        raise ValueError("PG_DB_URL environment variable not set. Database connection cannot be established.")
    return psycopg2.connect(os.environ.get("PG_DB_URL"))


def upsert_qbo_token(token: dict, realm_id: str, intuit_email: str = None):
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
                realm_id,
                intuit_email,
                access_token,
                refresh_token,
                token_type,
                expires_in,
                refresh_expires_in,
                issued_at_utc,
                access_token_expires_at,
                refresh_token_expires_at,
                qbo_environment,
                client_id,
                created_at,
                updated_at
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,to_timestamp(%s),to_timestamp(%s),%s,%s,now(),now())
            ON CONFLICT (realm_id, qbo_environment)
            DO UPDATE SET
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                expires_in = EXCLUDED.expires_in,
                refresh_expires_in = EXCLUDED.refresh_expires_in,
                issued_at_utc = EXCLUDED.issued_at_utc,
                access_token_expires_at = EXCLUDED.access_token_expires_at,
                refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
                intuit_email = EXCLUDED.intuit_email,
                updated_at = now();
            """,
            (
                realm_id,
                intuit_email,
                token.get("access_token"),
                token.get("refresh_token"),
                token.get("token_type", "bearer"),
                expires_in,
                refresh_expires_in,
                issued_at,
                access_expiry,
                refresh_expiry,
                QBO_ENV,
                CLIENT_ID,
            ),
        )

        conn.commit()
        cur.close()
        conn.close()

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
    print(f"DEBUG: Redirect URI being sent: {REDIRECT_URI}")
    return intuit.authorize_redirect(REDIRECT_URI, prompt="consent")

@APP.route("/callback")
def callback():
    token = intuit.authorize_access_token()
    realm_id = request.args.get("realmId")

    intuit_email = None
    if token.get("access_token"):
        resp = intuit.get(
            USERINFO_URL,
            token=token,
        )
        if resp.status_code == 200:
            intuit_email = resp.json().get("email")

    upsert_qbo_token(token, realm_id, intuit_email)

    return redirect(url_for("peek"))

# ------------------------------------------------------------------
# Peek from database
# ------------------------------------------------------------------
@APP.route("/peek")
def peek():
    conn = get_db_conn()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            realm_id,
            intuit_email,
            qbo_environment,
            updated_at
        FROM config.qbo_oauth_tokens
        ORDER BY updated_at DESC
        LIMIT 10;
        """
    )

    rows = cur.fetchall()
    cur.close()
    conn.close()

    return jsonify(
        [
            {
                "realm_id": r[0],
                "intuit_email": r[1],
                "environment": r[2],
                "updated_at": r[3].isoformat(),
            }
            for r in rows
        ]
    )


# ------------------------------------------------------------------
# Local dev only
# ------------------------------------------------------------------
if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=5000, debug=True)