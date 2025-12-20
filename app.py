import os
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise ValueError("No FLASK_SECRET_KEY found! Did you create the .env file?")

def get_db():
    db = sqlite3.connect("finance.db")
    db.row_factory = sqlite3.Row
    return db

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()
    cur = db.cursor()

    # 1. Alle Transaktionen des Users holen
    cur.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC", (session["user_id"],))
    transactions = cur.fetchall()

    # 2. Summen berechnen
    total_incomes = 0
    total_expenses = 0

    for row in transactions:
        if row["amount"] > 0:
            total_incomes += row["amount"]
        else:
            total_expenses += abs(row["amount"])

    balance = total_incomes - total_expenses
    
    db.close()

    return render_template("index.html", transactions=transactions,balance=balance, total_incomes=total_incomes, total_expenses=total_expenses)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return "must provide username and password", 400

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        db.close()

        if user is None or not check_password_hash(user["hash"], password):
            return "invalid username and/or password", 403

        session["user_id"] = user["id"]

        return redirect("/")
    
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not first_name or not username or not password or not confirmation:
            return "must provide all fields", 400
        if password != confirmation:
            return "passwords do not match", 400

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
    """Log user out"""

    session.clear()

    return redirect("/")

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """Allow user to change their password"""
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if not old_password or not new_password or not confirmation:
            return "must provide all fields", 400
        
        if new_password != confirmation:
            return "new passwords do not match", 400

        db = get_db()
        cur = db.cursor()
        
        cur.execute("SELECT hash FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()

        if not check_password_hash(user["hash"], old_password):
            db.close()
            return "incorrect old password", 403

        new_hash = generate_password_hash(new_password)
        cur.execute("UPDATE users SET hash = ? WHERE id = ?", (new_hash, session["user_id"]))
        db.commit()
        db.close()

        return redirect("/")
    
    else:
        return render_template("change_password.html")

@app.route("/add", methods=["GET", "POST"])
def add():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        amount = request.form.get("amount")
        category = request.form.get("category")
        description = request.form.get("description")

        if not amount or not category:
            return "Must provide amount and category", 400

        db = get_db()
        cur = db.cursor()
        
        cur.execute(
            "INSERT INTO transactions (user_id, amount, category, description) VALUES (?, ?, ?, ?)",
            (session["user_id"], amount, category, description)
        )
        
        db.commit()
        db.close()

        return redirect("/")

    else:
        return render_template("add.html")

if __name__ == "__main__":
    app.run(debug=True)