from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps


# defining some functions

# defining login_required function
def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# defining apology function
def apology(message, code=400):
    """Render message as an apology to user."""
    return render_template("apology.html", top=code, bottom=message)



# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
pdb = SQL("sqlite:///passwd.db")
ldb = SQL("sqlite:///login.db")

@app.route("/")
@login_required
def index():
    """Show the menu"""
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """The login page for users to login"""
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
        rows = ldb.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Remember the username of the logged user
        session["user's_name"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        if not username:
            return apology('Username Missing!')
        elif not password:
            return apology('Password Missing!')
        elif not confirmation:
            return apology('Confirm the password!')

        if password != confirmation:
            return apology("Password don't match")

        hash = generate_password_hash(password)

        try:
            ldb.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
            return redirect('/success')
        except:
            return apology('Username already registered!')

    else:
        return render_template("register.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/whoami")
@login_required
def whoami():
    """See the profile"""
    username = session["user's_name"]
    return render_template("whoami.html", username=username)

@app.route("/passwd")
@login_required
def passwd():
    """The actual Passwd table"""
    return render_template("passwd.html")

@app.route("/change_passwd", methods=["GET", "POST"])
@login_required
def change_passwd():
    """Change your Peter Passwd accounts password"""
    if request.method == "POST":
        id = session["user_id"]
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        if not password:
            return apology('Password Missing!')
        elif not confirmation:
            return apology('Confirm the password!')

        if password != confirmation:
            return apology("Password don't match")

        hash = generate_password_hash(password)

        try:
            ldb.execute("UPDATE users SET hash = ? WHERE id = ?", hash, id)
            return redirect("/success")
        except:
            return apology("something went wrong!")
    else:
        return render_template("change_passwd.html")

@app.route("/addpasswd", methods=["GET", "POST"])
@login_required
def addpasswd():
    """Add a passwd to the db"""
    if request.method == "POST":
        title = request.form.get('title')
        username = request.form.get('username')
        passwd = request.form.get('passwd')
        user_id = session["user_id"]

        if not title:
            return apology('Site/App Name missing!')
        elif not passwd:
            return apology('Password Missing!')
        elif not username:
            return apology('Username Missing!')

        try:
            pdb.execute("INSERT INTO creds (user_id, title, username, passwd) VALUES (?, ?, ?, ?)", user_id, title, username, passwd)
            return redirect("/success")
        except:
            return apology("There is already an entry with these credentials")
    else:
        return render_template("add_passwd.html")

@app.route("/delpasswd", methods=["GET", "POST"])
@login_required
def delpasswd():
    """Delete a passwd entry"""
    if request.method == "POST":
        title = request.form.get('title')
        username = request.form.get('username')
        passwd = request.form.get('passwd')

        if not title:
            return apology('Site/App Name missing!')
        elif not username:
            return apology('Username Missing!')

        try:
            pdb.execute("DELETE FROM creds WHERE title = ? AND username = ? AND passwd = ?", title, username, passwd)
            return redirect("/success")
        except:
            return apology("Something went wrong! Try again later")
    else:
        return render_template("delpasswd.html")

@app.route("/success")
def success():
    """A page to show for any successful attempt"""
    return render_template("success.html")

@app.route("/seepasswd")
@login_required
def seepasswd():
    """Show user their entries"""
    user_id = session["user_id"]
    passwds = pdb.execute("SELECT title, username, passwd FROM creds WHERE user_id = ?", user_id)

    return render_template("seepasswd.html", passwds=passwds)


@app.route("/about")
def about():
    """Info about my webapp"""
    return render_template("about.html")