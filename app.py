import os
import json
import secrets
from flask import Flask, redirect, request, url_for, session, render_template
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests
import mysql.connector
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET")

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

# Remove the index route and its usage

@app.route("/login")
def login():
    nonce = secrets.token_urlsafe(16)
    session["nonce"] = nonce
    redirect_uri = url_for("callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route("/callback")
def callback():
    # Get token and parse user info
    token = oauth.google.authorize_access_token()
    session["token"] = token  # Save token in session for later use

    userinfo = oauth.google.parse_id_token(token, nonce=session.get("nonce"))

    # Save info to session
    session["user"] = {
        "name": userinfo["name"],
        "email": userinfo["email"],
        "picture": userinfo["picture"]
    }

    admin_emails = {"admin@example.com", "anotheradmin@example.com"}  # Add all admin emails here

    # Determine role
    if userinfo["email"] in admin_emails:
        role = "admin"
    else:
        role = "user"

    # Save to MySQL database (always update role on login)
    conn = get_db_connection()
    cur = conn.cursor()
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
        userinfo["name"],
        userinfo["email"],
        userinfo["picture"],
        token.get("access_token"),
        token.get("id_token"),
        role
    ))
    conn.commit()
    cur.close()
    conn.close()

    # Redirect based on role
    REDIRECT_ADMIN_URL = os.getenv("REDIRECT_ADMIN_URL", "http://localhost:3000/admin")
    REDIRECT_SELECTION_URL = os.getenv("REDIRECT_SELECTION_URL", "http://localhost:3000/selection")
    if role == "admin":
        return redirect(REDIRECT_ADMIN_URL)
    else:
        return redirect(REDIRECT_SELECTION_URL)

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
    return oauth.microsoft.authorize_redirect(redirect_uri, nonce=nonce)

# Microsoft OAuth callback route
@app.route("/callback-microsoft")
def callback_microsoft():
    token = oauth.microsoft.authorize_access_token()
    session["token"] = token
    userinfo = oauth.microsoft.parse_id_token(token, nonce=session.get("nonce"))

    session["user"] = {
        "name": userinfo.get("name"),
        "email": userinfo.get("email"),
        "picture": userinfo.get("picture")
    }

    admin_emails = {"admin@example.com", "anotheradmin@example.com"}  # Add all admin emails here
    if userinfo.get("email") in admin_emails:
        role = "admin"
    else:
        role = "user"

    conn = get_db_connection()
    cur = conn.cursor()
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
    cur.close()
    conn.close()

    REDIRECT_ADMIN_URL = os.getenv("REDIRECT_ADMIN_URL", "http://localhost:3000/admin")
    REDIRECT_SELECTION_URL = os.getenv("REDIRECT_SELECTION_URL", "http://localhost:3000/selection")
    if role == "admin":
        return redirect(REDIRECT_ADMIN_URL)
    else:
        return redirect(REDIRECT_SELECTION_URL)

@app.route("/test-callback", methods=["POST"])
def test_callback():
    data = request.json
    userinfo = data.get("userinfo")
    token = data.get("token")
    role = data.get("role", "user")  # Default to 'user' if not provided

    # Save info to session (optional for test)
    session["user"] = {
        "name": userinfo["name"],
        "email": userinfo["email"],
        "picture": userinfo["picture"]
    }

    # Save to MySQL database
    conn = get_db_connection()
    cur = conn.cursor()
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
        userinfo["name"],
        userinfo["email"],
        userinfo["picture"],
        token.get("access_token"),
        token.get("id_token"),
        role
    ))
    conn.commit()
    cur.close()
    conn.close()

    return {"status": "success", "message": "Test user inserted/updated."}

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
