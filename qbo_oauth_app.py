import os
from datetime import datetime, timezone, timedelta
import requests

from dotenv import load_dotenv
from flask import Flask, request, render_template_string
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix

import psycopg2

# ------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------
load_dotenv()

APP = Flask(__name__)
APP.secret_key = os.getenv("FLASK_SECRET_KEY")

APP.wsgi_app = ProxyFix(APP.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

APP.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=90),
)

PG_DB_URL = os.getenv("PG_DB_URL")

CLIENT_ID = os.getenv("INTUIT_CLIENT_ID")
CLIENT_SECRET = os.getenv("INTUIT_CLIENT_SECRET")
REDIRECT_URI = os.getenv("INTUIT_REDIRECT_URI")
QBO_ENV = (os.getenv("QBO_ENV", "sandbox") or "sandbox").lower()

AUTH_URL = "https://appcenter.intuit.com/connect/oauth2"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
USERINFO_URL = "https://accounts.platform.intuit.com/v1/openid_connect/userinfo"

SCOPE = "com.intuit.quickbooks.accounting openid email profile"

RETURN_URL = (
    "https://datachamp-finance-58111015615.asia-south1.run.app/"
    "dashboard/sourceintegration?source=quickbooks"
)

# ------------------------------------------------------------------
# OAuth client
# ------------------------------------------------------------------
oauth = OAuth(APP)

intuit = oauth.register(
    name="intuit",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    authorize_url=AUTH_URL,
    client_kwargs={"scope": SCOPE},
)

# ------------------------------------------------------------------
# Database helpers
# ------------------------------------------------------------------
def get_db_conn():
    if not PG_DB_URL:
        raise RuntimeError("PG_DB_URL not set")
    return psycopg2.connect(PG_DB_URL)

def upsert_qbo_token(
    token: dict,
    realm_id: str,
    tenant_id: str,
    intuit_email: str = None,
    intuit_user_id: str = None,
):
    conn = None
    cur = None
    try:
        conn = get_db_conn()
        cur = conn.cursor()

        issued_at = datetime.now(timezone.utc)

        expires_in = token.get("expires_in")
        refresh_expires_in = token.get("x_refresh_token_expires_in")

        access_expiry = issued_at.timestamp() + expires_in if expires_in else None
        refresh_expiry = issued_at.timestamp() + refresh_expires_in if refresh_expires_in else None

        cur.execute(
            """
            INSERT INTO config.qbo_oauth_tokens (
                tenant_id,
                realm_id,
                intuit_user_id,
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
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    to_timestamp(%s),to_timestamp(%s),
                    %s,%s,now(),now())
            ON CONFLICT (tenant_id, realm_id, qbo_environment)
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
                tenant_id,
                realm_id,
                intuit_user_id,
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
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ------------------------------------------------------------------
# OAuth flow
# ------------------------------------------------------------------
@APP.route("/start")
def start():
    tenant_id = request.args.get("tenant_id")
    if not tenant_id:
        return "Missing tenant_id", 400

    return render_template_string(
        """
        <!doctype html>
        <html>
          <body style="font-family: system-ui; text-align:center; margin-top:20%">
            <p>Please wait… Connecting to QuickBooks</p>
            <script>
              setTimeout(function() {
                window.location.href = "/oauth?tenant_id={{ tenant_id }}";
              }, 1200);
            </script>
          </body>
        </html>
        """,
        tenant_id=tenant_id,
    )

@APP.route("/oauth")
def oauth_start():
    tenant_id = request.args.get("tenant_id")
    if not tenant_id:
        return "Missing tenant context", 400

    # IMPORTANT: tenant_id is passed via OAuth state
    return intuit.authorize_redirect(
        REDIRECT_URI,
        state=tenant_id,
        prompt="consent",
    )

@APP.route("/callback")
def callback():
    code = request.args.get("code")
    realm_id = request.args.get("realmId")
    tenant_id = request.args.get("state")  # ← FIX

    if not code or not realm_id or not tenant_id:
        return "Invalid OAuth response", 400

    try:
        response = requests.post(
            TOKEN_URL,
            auth=(CLIENT_ID, CLIENT_SECRET),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
            timeout=10,
        )
        token = response.json()

        intuit_email = None
        intuit_user_id = None

        if token.get("access_token"):
            r = requests.get(
                USERINFO_URL,
                headers={"Authorization": f"Bearer {token['access_token']}"},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                intuit_email = data.get("email")
                intuit_user_id = data.get("sub")

        upsert_qbo_token(
            token=token,
            realm_id=realm_id,
            tenant_id=tenant_id,
            intuit_email=intuit_email,
            intuit_user_id=intuit_user_id,
        )

    except Exception as e:
        APP.logger.exception("OAuth callback failure")
        return "Authentication failed", 500

    return render_template_string(
        """
        <!doctype html>
        <html>
          <body style="font-family: system-ui; text-align:center; margin-top:20%">
            <p>QuickBooks connected successfully</p>
            <script>
              setTimeout(function() {
                window.location.href = "{{ url }}";
              }, 1200);
            </script>
          </body>
        </html>
        """,
        url=RETURN_URL,
    )

if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=5000)
    