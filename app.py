import imp
import os
import requests
import urllib.parse
from cs50 import SQL

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, apology

from functools import wraps

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Connect database
db = SQL("sqlite:///login.db")

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Take info from db
    account = db.execute("SELECT login FROM users WHERE id = :id", id=session["user_id"])
    account = account[0]['login']
    return render_template("index.html", account=account)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Check if username was provided by user
        if not request.form.get("username"):
            return apology("Must provide username", 400)

        # Check if password was provided by user
        if not request.form.get("password") or not request.form.get("confirmation"):
            return apology("Must provide password", 400)

        # Query database for similar username
        login = db.execute("SELECT * FROM users WHERE login = ?", request.form.get("username"))

        # Ensure if username already exists
        if len(login) == 1:
            return apology("Username already exist")

        # Ensure if passwords do match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords do not match", 400)

        # Perfome hash function to password
        pass_hash = generate_password_hash(request.form.get("password"))

        # Insert login and password to database
        username = request.form.get("username")
        db.execute("INSERT INTO users (login, password) VALUES (?, ?)", username, pass_hash)

        # Login user
        rows = db.execute("SELECT * FROM users WHERE login = ?", request.form.get("username"))
        print(rows[0]["id"])
        session["user_id"] = rows[0]["id"]
        print(session["user_id"])

        # Redirect user to main page and flash a message what he/she successful registered
        flash("Registered!")
        return redirect("/")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE login = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)





