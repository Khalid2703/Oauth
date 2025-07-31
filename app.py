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
    if role == "admin":
        return redirect("https://edtech-six-navy.vercel.app/admin")
    else:
        return redirect("https://edtech-six-navy.vercel.app/selection")

@app.route("/logout")
def logout():
    session.clear()
    return "Logged out. You may close this window."

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
    app.run(debug=True)
