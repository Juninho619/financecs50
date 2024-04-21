import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    transactions_db = db.execute(
        "SELECT symbol, SUM(shares) AS shares, price FROM transactions WHERE user_id=? GROUP BY symbol", user_id)
    cash_db = db.execute("SELECT cash FROM users WHERE id=?", user_id)
    cash = cash_db[0]["cash"]

    return render_template("index.html", database=transactions_db, cash=usd(cash),)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Make sure the user entered input
        if not request.form.get("symbol"):
            return apology("Please enter a valid symbol")

        # Same for shares
        elif not request.form.get("shares"):
            return apology("Please enter valid shares")

        if not lookup(request.form.get("symbol")):
            return apology("Please enter a valid symbol")

        shares = int(request.form.get("shares"))

        if shares < 0:
            return apology("shares must be a positive integer", 400)

        try:
            shares=int(shares)
            assert shares > 0
        except ValueError as ex:
            return apology("Shares must be apositive integer", 400)

        # Use lookup function
        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)

         # Make sure the user has enough money
        user_cash = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
        cash = user_cash[0]["cash"]

        # Make the needed substraction
        beetlebum = shares * stock['price']
        subdcash = cash - beetlebum

        # Can't proceed if user doesn't have enough money
        if subdcash < 0:
            return apology("Sorry. You do not possess enough money to make this transaction")

        # Update the user's database
        db.execute("UPDATE users SET cash=:subdcash WHERE id=:id", subdcash=subdcash, id=session["user_id"]);

        # Update the transaction's table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)", user_id=session["user_id"], symbol=stock['symbol'], shares=shares, price=stock['price'])

        # Notice the user the transaction was successful
        flash("Transaction successfully completed")

        return redirect("/")

    # Get method
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT symbol, shares, price FROM transactions WHERE user_id=:user_id", user_id=session["user_id"])
    for i in range(len(transactions)):
        transactions[i]["price"] = usd(transactions[i]["price"])

    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

 # User reached route via GET (as by clicking a link or via redirect)
    else:
       return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    # Create templates quote.html and quoted.html
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Invalid symbol", 400)
        get_quote = lookup(symbol)
        if not get_quote:
            return apology("Invalid symbol", 400)
        name = get_quote["name"]
        price = get_quote["price"]
        return render_template("quoted.html", name=name, symbol=symbol.upper(), price=usd(price))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ask user input to register
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        hash = generate_password_hash(password)

        # Make sure username field wasn't left blank
        if not request.form.get("username"):
            return apology("Please enter a valid username")

        # Make sure password field wasn't left blank
        elif not request.form.get("password"):
            return apology("Please enter a valid password")

        # Make sure confirmation wasn't left blank
        elif not request.form.get("confirmation"):
            return apology("Please re-enter your password")

        # Check if passwords are identical
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match")

        # Query usernames in the internet
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Make sure username isn't already taken
        if len(rows) != 0:
            return apology("Sorry, this username was already taken. Please choose another")

        # Insert newly registered user into the users database
        new_user = db.execute(
            "INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

        # Keep the session going
        session["user_id"] = new_user

        # Redirect user to the homepage
        return redirect("/")

    # If user enters the page via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method =="POST":

        # Make sure stock wasn't left blank
        if not request.form.get("symbol"):
            return apology("Please enter a valid symbol")

        # Make sure shares wasn't left blank
        elif not request.form.get("shares"):
            return apology("Please enter a valid share")

        # Make sure share is positive
        elif int(request.form.get("shares")) < 0:
            return apology("Shares must be above 0")

        # Make sure symbol is valid
        if not lookup(request.form.get("symbol")):
            return apology("Symbol couldn't be found. Please enter another")

        # Use lookup function
        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)

        rows = db.execute("SELECT symbol, SUM(shares) FROM transactions WHERE user_id=:user_id GROUP BY symbol HAVING SUM(shares) > 0", user_id=session["user_id"])

        # Initialize values at stake
        shares = int(request.form.get("shares"))
        for row in rows:
            if row["symbol"] == symbol:
                if shares > row["SUM(shares)"]:
                    return apology("You cannot sell more shares than you possess")

        # Set transaction value
        transaction = shares * stock["price"]

        # Make sure user has enough cash
        user_cash = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
        cash = user_cash[0]["cash"]

        # Ensure user has enough shares
        user_shares = db.execute("SELECT SUM(shares) as totalShares FROM trades WHERE symbol = ? AND user_id = ? HAVING totalShares > 0", symbol,)

        if shares > user_shares:
            return apology("You don't have that many shares")

        # Substract the money spent
        subdcash = cash + transaction

        # Update money acquired
        db.execute("UPDATE users SET cash=:subdcash WHERE id=:id", subdcash=subdcash, id=session["user_id"])

        # Update transactions table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)", user_id=session["user_id"], symbol=stock['symbol'], shares= -1 * shares, price=stock['price'])

        # Inform user sale was successful
        flash("Sale completed successfully")
        return redirect("/")

    # Get method
    else:
        rows = db.execute("SELECT symbol FROM transactions WHERE user_id=:user_id GROUP BY symbol HAVING SUM(shares) > 0", user_id=session["user_id"])
        return render_template("sell.html", symbols = [row["symbol"] for row in rows])


@app.route("/change password", methods=["GET", "POST"])
def change_password():
    # Allow user to change password
    new_password = request.form.get("new password")
    confirm_new_password = request.form.get("confirm new password")

    # Make sure they are both the same
    if new_password != confirm_new_password:
        return apology("passwords do not match")

    # Make sure password is entered
    if new_password == "":
        return apology("please enter a valid password")
