from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = "dev-secret"

def get_db():
    return sqlite3.connect("finance.db")

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()

        if row and check_password_hash(row[1], password):
            session["user_id"] = row[0]
            return redirect("/")
        return "Invalid credentials"

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        hash_pw = generate_password_hash(password)
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            (username, hash_pw)
        )
        db.commit()
        return redirect("/login")

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)