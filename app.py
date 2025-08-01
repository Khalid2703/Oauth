import os
import secrets
from flask import Flask, redirect, request, url_for, session
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests
import mysql.connector
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix  # ✅ Added

load_dotenv()

app = Flask(__name__)

# ✅ ProxyFix: Respect headers from reverse proxies (e.g. Render)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# ✅ HTTPS Redirect: Ensure HTTPS on all requests
@app.before_request
def before_request():
    if not request.is_secure:
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

# Secure session handling
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Load OAuth credentials
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET")

# Admin email list
ADMIN_EMAIL_LIST = os.getenv("ADMIN_EMAILS", "admin@example.com,anotheradmin@example.com")
ADMIN_EMAILS = set(email.strip() for email in ADMIN_EMAIL_LIST.split(','))

# Frontend URL for CORS and redirects
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# OAuth configuration
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"}
)
oauth.register(
    name='microsoft',
    client_id=MICROSOFT_CLIENT_ID,
    client_secret=MICROSOFT_CLIENT_SECRET,
    server_metadata_url='https://login.microsoftonline.com/344fd090-c4e0-467a-9e2b-325686b01143/v2.0/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)


# ✅ Secure CORS: Restrict to your frontend's origin for better security.
# `supports_credentials=True` is needed for sessions/cookies to work across domains.
CORS(app, origins=[FRONTEND_URL], supports_credentials=True)

def get_db_connection():
    conn = mysql.connector.connect(
        host=os.getenv("MYSQL_HOST"),
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        database=os.getenv("MYSQL_DATABASE"),
        port=int(os.getenv("MYSQL_PORT", 3306))
    )
    return conn

def _process_oauth_callback(provider_name):
    """Process both Google and Microsoft OAuth callbacks."""
    provider = oauth._clients[provider_name]
    token = provider.authorize_access_token()
    session["token"] = token  # Note: Storing full tokens in session is not always best practice for production
    userinfo = provider.parse_id_token(token, nonce=session.get("nonce"))
    session["user"] = {
        "name": userinfo.get("name"),
        "email": userinfo.get("email"),
        "picture": userinfo.get("picture")
    }
    session["provider"] = provider_name # Store the provider for logout
    role = "admin" if userinfo.get("email") in ADMIN_EMAILS else "user"

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

    # Use the base FRONTEND_URL for redirects
    REDIRECT_ADMIN_URL = f"{FRONTEND_URL}/admin"
    REDIRECT_SELECTION_URL = f"{FRONTEND_URL}/selection"
    return redirect(REDIRECT_ADMIN_URL) if role == "admin" else redirect(REDIRECT_SELECTION_URL)

@app.route("/login/<provider_name>")
def login(provider_name):
    """Generic login route for any registered OAuth provider."""
    if provider_name not in oauth._clients:
        return "Unknown provider", 404

    nonce = secrets.token_urlsafe(16)
    session["nonce"] = nonce
    # Use the generic callback route
    redirect_uri = url_for("callback", provider_name=provider_name, _external=True)
    print(f"[DEBUG] {provider_name.capitalize()} OAuth redirect_uri: {redirect_uri}")
    return oauth._clients[provider_name].authorize_redirect(redirect_uri, nonce=nonce)

@app.route("/callback/<provider_name>")
def callback(provider_name):
    """Generic callback route for any registered OAuth provider."""
    if provider_name not in oauth._clients:
        return "Unknown provider", 404
    return _process_oauth_callback(provider_name)

@app.route("/logout")
def logout():
    """Logs the user out of the application and the identity provider."""
    # Get the provider name and token from the session before clearing it
    provider_name = session.get("provider")
    token = session.get("token")

    # Clear the local application session
    session.clear()

    # If the user logged in with an OAuth provider, redirect to their logout page
    if provider_name and provider_name in oauth._clients:
        provider = oauth._clients[provider_name]
        logout_endpoint = provider.server_metadata.get('end_session_endpoint')

        if logout_endpoint:
            # For OIDC, it's good practice to include id_token_hint
            id_token_hint = token.get('id_token') if token else None
            logout_url = f"{logout_endpoint}?post_logout_redirect_uri={FRONTEND_URL}"
            if id_token_hint:
                logout_url += f"&id_token_hint={id_token_hint}"
            return redirect(logout_url)

    # Fallback redirect to the frontend
    return redirect(FRONTEND_URL)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
