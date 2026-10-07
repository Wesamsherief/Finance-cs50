import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Secret key for sessions and flash messages
app.secret_key = os.environ.get("SECRET_KEY", "fallback-dev-secret-key")

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure Database Connection (Supports PostgreSQL in production & fallback to SQLite)
db_url = os.environ.get("DATABASE_URL")
if db_url:
    # Heroku / Render use "postgres://", which SQLAlchemy / cs50 expects as "postgresql://"
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    db = SQL(db_url)
else:
    db = SQL(f"sqlite:///{os.path.join(app.root_path, 'finance.db')}")


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
    rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = rows[0]["cash"]

    stocks = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0",
        session["user_id"],
    )

    portfolio = []
    grand_total = cash

    for stock in stocks:
        quote = lookup(stock["symbol"])
        if quote:
            stock_value = stock["total_shares"] * quote["price"]
            portfolio.append(
                {
                    "symbol": stock["symbol"],
                    "shares": stock["total_shares"],
                    "price": quote["price"],
                    "total": stock_value,
                }
            )
            grand_total += stock_value

    return render_template(
        "index.html", portfolio=portfolio, cash=cash, grand_total=grand_total
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if symbol:
            symbol = symbol.upper()
        shares = request.form.get("shares")

        if not symbol:
            return apology("must provide symbol", 400)
        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("must provide positive integer number of shares", 400)

        shares = int(shares)
        quote = lookup(symbol)

        if not quote:
            return apology("invalid symbol", 400)

        total_cost = shares * quote["price"]

        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = rows[0]["cash"]

        if total_cost > cash:
            return apology("can't afford", 400)

        db.execute(
            "UPDATE users SET cash = cash - ? WHERE id = ?",
            total_cost,
            session["user_id"],
        )

        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            session["user_id"],
            symbol,
            shares,
            quote["price"],
        )

        flash("Bought!")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT symbol, shares, price, transacted FROM transactions WHERE user_id = ? ORDER BY transacted DESC",
        session["user_id"],
    )

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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)

        quote = lookup(symbol)
        if not quote:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", quote=quote)
    else:
        return render_template("quote.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user's password"""
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if not current_password:
            return apology("must provide current password", 400)
        if not new_password:
            return apology("must provide new password", 400)
        if new_password != confirmation:
            return apology("new passwords do not match", 400)

        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        if not check_password_hash(rows[0]["hash"], current_password):
            return apology("current password is incorrect", 400)

        new_hash = generate_password_hash(new_password)
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"]
        )

        flash("Password changed successfully!")
        return redirect("/")
    else:
        return render_template("change_password.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username", 400)
        if not password:
            return apology("must provide password", 400)
        if password != confirmation:
            return apology("passwords do not match", 400)

        hash = generate_password_hash(password)

        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)", username, hash
            )
        except Exception:
            return apology("username already exists", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("must select symbol", 400)

        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("must have positive integer number of shares", 400)

        shares = int(shares)
        rows = db.execute(
            "SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol",
            session["user_id"],
            symbol,
        )

        if not rows or rows[0]["total_shares"] < shares:
            return apology("not enough shares", 400)

        quote = lookup(symbol)
        if not quote:
            return apology("invalid symbol", 400)

        total_value = shares * quote["price"]

        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?",
            total_value,
            session["user_id"],
        )
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            session["user_id"],
            symbol,
            -shares,
            quote["price"],
        )

        flash("Sold!")
        return redirect("/")

    else:
        stocks = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0",
            session["user_id"],
        )

        return render_template("sell.html", stocks=stocks)


# Entry point for production execution
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
