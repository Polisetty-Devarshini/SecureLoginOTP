import os
import random
import time

import MySQLdb
import bcrypt
from dotenv import load_dotenv
from flask import Flask, render_template, request, session


# ---------------- LOAD ENVIRONMENT ----------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_FILE)


# ---------------- FLASK ----------------

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is missing in .env")


# ---------------- MYSQL CONNECTION ----------------

def get_db_connection():
    return MySQLdb.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        passwd=os.getenv("MYSQL_PASSWORD"),
        db=os.getenv("MYSQL_DB", "secure_login"),
        port=int(os.getenv("MYSQL_PORT", "3306"))
    )


# ---------------- REGISTER ----------------

@app.route("/", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        try:
            db = get_db_connection()
            cur = db.cursor()

            cur.execute(
                """
                INSERT INTO users (username, email, password)
                VALUES (%s, %s, %s)
                """,
                (username, email, hashed_password)
            )

            db.commit()

            cur.close()
            db.close()

            return "Registration Successful! <a href='/login'>Login</a>"

        except Exception as e:
            return f"Registration Error: {e}"

    return render_template("register.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        try:
            db = get_db_connection()
            cur = db.cursor()

            cur.execute(
                "SELECT password FROM users WHERE username = %s",
                (username,)
            )

            user = cur.fetchone()

            cur.close()
            db.close()

            if user:

                stored_password = user[0]

                if isinstance(stored_password, str):
                    stored_password = stored_password.encode("utf-8")

                if bcrypt.checkpw(
                    password.encode("utf-8"),
                    stored_password
                ):

                    otp = str(random.randint(100000, 999999))

                    session["otp"] = otp
                    session["username"] = username
                    session["otp_time"] = time.time()

                    return render_template(
                        "otp.html",
                        otp=otp
                    )

            return "Invalid username or password!"

        except Exception as e:
            return f"Login Error: {e}"

    return render_template("login.html")


# ---------------- OTP VERIFICATION ----------------

@app.route("/verify-otp", methods=["POST"])
def verify_otp():

    entered_otp = request.form["otp"].strip()

    stored_otp = session.get("otp")
    otp_time = session.get("otp_time")
    username = session.get("username")

    if not stored_otp or not otp_time:
        return "OTP expired. Please login again."

    if time.time() - otp_time > 300:
        session.clear()
        return "OTP expired. Please login again."

    if entered_otp == stored_otp:

        session.clear()

        return f"Login Successful! Welcome {username}."

    return "Invalid OTP!"


# ---------------- START APPLICATION ----------------

if __name__ == "__main__":
    app.run(debug=True)