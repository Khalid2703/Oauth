import os
import secrets
from flask import Flask, redirect, request, url_for, session
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests
import mysql.connector
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
# It's critical to use a static secret key for session management.
# Using os.urandom() will generate a new key on each app restart,
# invalidating all existing user sessions.
app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise ValueError("No FLASK_SECRET_KEY set for Flask application")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET")

# Centralize configuration
ADMIN_EMAIL_LIST = os.getenv("ADMIN_EMAILS", "admin@example.com,anotheradmin@example.com")
ADMIN_EMAILS = set(email.strip() for email in ADMIN_EMAIL_LIST.split(','))

oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)
oauth.register(
    name='microsoft',
    client_id=MICROSOFT_CLIENT_ID,
    client_secret=MICROSOFT_CLIENT_SECRET,
    server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

CORS(app)

def get_db_connection():
    conn = mysql.connector.connect(
        host=os.getenv("MYSQL_HOST"),
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        database=os.getenv("MYSQL_DATABASE"),
        port=int(os.getenv("MYSQL_PORT", 3306))
    )
    return conn

def _process_oauth_callback(provider):
    """A generic helper to process OAuth callbacks, reducing code duplication."""
    token = provider.authorize_access_token()
    session["token"] = token
    userinfo = provider.parse_id_token(token, nonce=session.get("nonce"))
    session["user"] = {
        "name": userinfo.get("name"),
        "email": userinfo.get("email"),
        "picture": userinfo.get("picture")
    }
    role = "admin" if userinfo.get("email") in ADMIN_EMAILS else "user"

    # Use context managers for safer database handling
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (name, email, picture, access_token, id_token, role)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        name=VALUES(name),
                        picture=VALUES(picture),
                        access_token=VALUES(access_token),
                        id_token=VALUES(id_token),
                        role=VALUES(role)
                """, (
                    userinfo.get("name"),
                    userinfo.get("email"),
                    userinfo.get("picture"),
                    token.get("access_token"),
                    token.get("id_token"),
                    role
                ))
                conn.commit()
    except mysql.connector.Error as err:
        app.logger.error(f"Database error during OAuth callback: {err}")
        return "A database error occurred. Please try again later.", 500

    REDIRECT_ADMIN_URL = os.getenv("REDIRECT_ADMIN_URL", "http://localhost:3000/admin")
    REDIRECT_SELECTION_URL = os.getenv("REDIRECT_SELECTION_URL", "http://localhost:3000/selection")
    return redirect(REDIRECT_ADMIN_URL) if role == "admin" else redirect(REDIRECT_SELECTION_URL)

@app.route("/login")
def login():
    nonce = secrets.token_urlsafe(16)
    session["nonce"] = nonce
    redirect_uri = url_for("callback", _external=True)
    print(f"[DEBUG] Google OAuth redirect_uri: {redirect_uri}")
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route("/callback")
def callback():
    return _process_oauth_callback(oauth.google)

@app.route("/logout")
def logout():
    session.clear()
    return "Logged out. You may close this window."

# Microsoft OAuth login route
@app.route("/login-microsoft")
def login_microsoft():
    nonce = secrets.token_urlsafe(16)
    session["nonce"] = nonce
    redirect_uri = url_for("callback_microsoft", _external=True)
    print(f"[DEBUG] Microsoft OAuth redirect_uri: {redirect_uri}")
    return oauth.microsoft.authorize_redirect(redirect_uri, nonce=nonce)

# Microsoft OAuth callback route
@app.route("/callback-microsoft")
def callback_microsoft():
    return _process_oauth_callback(oauth.microsoft)

#
# WARNING: This test endpoint is a major security risk.
# It allows unauthenticated insertion/updating of user data.
# It should be removed or protected (e.g., by checking FLASK_ENV) in production.
# I have commented it out for safety.
#
# @app.route("/test-callback", methods=["POST"])
# def test_callback():
#     data = request.json
#     userinfo = data.get("userinfo")
#     token = data.get("token")
#     role = data.get("role", "user")  # Default to 'user' if not provided
#
#     session["user"] = {
#         "name": userinfo["name"],
#         "email": userinfo["email"],
#         "picture": userinfo["picture"]
#     }
#
#     try:
#         with get_db_connection() as conn:
#             with conn.cursor() as cur:
#                 cur.execute("""
#                     INSERT INTO users (name, email, picture, access_token, id_token, role)
#                     VALUES (%s, %s, %s, %s, %s, %s)
#                     ON DUPLICATE KEY UPDATE
#                         name=VALUES(name), picture=VALUES(picture),
#                         access_token=VALUES(access_token), id_token=VALUES(id_token),
#                         role=VALUES(role)
#                 """, (
#                     userinfo.get("name"), userinfo.get("email"), userinfo.get("picture"),
#                     token.get("access_token"), token.get("id_token"), role
#                 ))
#                 conn.commit()
#     except mysql.connector.Error as err:
#         app.logger.error(f"Database error during test callback: {err}")
#         return {"status": "error", "message": "Database error"}, 500
#
#     return {"status": "success", "message": "Test user inserted/updated."}

if __name__ == "__main__":
    # The host '0.0.0.0' makes the server accessible from your network,
    # which is useful for development and containerization.
    # The second app.run() call was unreachable.
    app.run(debug=True, host="0.0.0.0", port=5000)
