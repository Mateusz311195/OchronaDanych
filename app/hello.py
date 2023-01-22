# importy do flaska
from flask import Flask, render_template, request, make_response, redirect, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# import do markdown
import markdown
from collections import deque
# import do hashowania
from passlib.hash import sha256_crypt
# inne importy
import sqlite3
import os
import requests
import bleach
import time
from math import log2

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

DATABASE = "./sqlite3.db"

global ID, PASSWD_RENDERED
ID = 0
PASSWD_RENDERED = ''


limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


def shannon_entropy(string):
    entropy = 0.0
    size = len(string)
    for i in range(256):
        prob = string.count(chr(i)) / size
        if prob > 0.0:
            entropy += prob * log2(prob)
    return -entropy


class User(UserMixin):
    pass


@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(
        f"SELECT username, password FROM user WHERE username = '{username}'")
    row = sql.fetchone()
    try:
        username, password = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user


recent_users = deque(maxlen=3)


@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        time.sleep(2)  # Opóźnienie logowania utrudniające zdalne zgadywanie
        # Zabezpieczenie przed znakami specjalnymi których nie chcemy w tym miejscu
        username = bleach.clean(request.form.get("username"))
        password = bleach.clean(request.form.get("password"))
        user = user_loader(username)

        if user is None:
            return "Nieprawidłowy login lub hasło", 401
        if sha256_crypt.verify(password, user.password):
            limiter.reset()
            login_user(user)
            return redirect('/hello')
        else:
            return "Nieprawidłowy login lub hasło", 401


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@app.route("/hello", methods=['GET'])
@login_required
def hello():
    if request.method == 'GET':
        print(current_user.id)
        username = current_user.id

        db = sqlite3.connect(DATABASE)
        sql = db.cursor()

        sql.execute(
            f"SELECT id FROM notes WHERE username == '{username}' AND notepassword IS NULL")
        unprotected_notes = sql.fetchall()

        sql.execute(f"SELECT id FROM notes WHERE shared == 'true'")
        shared_notes = sql.fetchall()

        sql.execute(
            f"SELECT id FROM notes WHERE username == '{username}' AND notepassword IS NOT NULL")
        protected_notes = sql.fetchall()

        return render_template("hello.html", username=username, notes=unprotected_notes, shared_notes=shared_notes, protected_notes=protected_notes)


@app.route("/render", methods=['POST'])
@login_required
def render():
    # blokowanie niepożądanych opcji
    md = bleach.clean(request.form.get("markdown", ""))
    rendered = markdown.markdown(md)
    shared = request.form.get("shared")
    if shared is None:
        shared = "false"
    # blokowanie niepożądanych opcji
    note_password = bleach.clean(request.form.get("note_password"))
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    if (len(note_password) == 0):
        sql.execute(
            f"INSERT INTO notes (username, note, shared) VALUES ('{username}', '{rendered}', '{shared}')")
        db.commit()
    elif len(note_password) != 0 and shared == "true":
        return "Nie możesz udostępniać chronionej notatki. Notatka nie została zapisana", 401
    else:
        sql.execute(
            f"INSERT INTO notes (username, note, notepassword) VALUES ('{username}', '{rendered}', '{sha256_crypt.hash(note_password)}')")
        db.commit()
    return render_template("markdown.html", rendered=rendered)


@app.route("/render/<rendered_id>")
@login_required
def render_old(rendered_id):
    global ID
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(
        f"SELECT username, note, notepassword FROM notes WHERE id == {rendered_id}")

    try:
        username, rendered, notepassword = sql.fetchone()
        sql.execute(f"SELECT shared FROM notes WHERE id == {rendered_id}")
        shared = sql.fetchone()

        if username != current_user.id:
            if shared:
                return render_template("markdown.html", rendered=rendered)
            return "Nie masz dostępu do tej notatki", 403
        if notepassword is not None:
            ID = rendered_id
            return redirect("/hello/unlock")
        else:
            return render_template("markdown.html", rendered=rendered)
    except:
        return "Nie znaleziono notatki", 404


@app.route("/hello/unlock", methods=['GET', 'POST'])
@login_required
def get_passwd():
    global ID, PASSWD_RENDERED
    if request.method == 'GET':
        return render_template("get_passwd.html")
    if request.method == 'POST':
        note_password_form = request.form.get("note_password")

        db = sqlite3.connect(DATABASE)
        sql = db.cursor()

        sql.execute(f"SELECT note, notepassword FROM notes WHERE id == {ID}")
        rendered, notepassword = sql.fetchone()
        PASSWD_RENDERED = rendered
        if sha256_crypt.verify(note_password_form, notepassword) == True:
            return redirect("/rendered/unlocked")
        else:
            return "Hasło nie było poprawne", 401


@app.route("/rendered/unlocked")
@login_required
def show_passwd_note():
    global PASSWD_RENDERED
    rendered = PASSWD_RENDERED
    return render_template("show_passwd_note.html", rendered=rendered)


@app.route("/user/register", methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    if request.method == 'POST':
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()

        # Zabezpieczenie przed znakami specjalnymi których nie chcemy w tym miejscu
        username = bleach.clean(request.form.get('username'))
        password = bleach.clean(request.form.get('password'))

        if request.form["username"] != "" and request.form["password"] != "":

            if (len(password) < 8):
                return render_template("error_register.html", msg="Hasło musi mieć przynajmniej 8 znaków")
            if (shannon_entropy(password) < 3):
                return render_template("error_register.html", msg="Hasło jest zbyt słabe.")

            sql.execute(f"SELECT * FROM user WHERE username == '{username}'")
            userExists = sql.fetchone()

            if userExists:
                return "The username is taken.", 401
            else:
                sql.execute(
                    f"INSERT INTO user (username, password) VALUES ('{username}', '{sha256_crypt.hash(password)}');")
                db.commit()
                return render_template("index.html")
        else:
            return "Login i/lub hasło nie mogą być puste", 401


if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute(
        "CREATE TABLE user (username VARCHAR(32), password VARCHAR(128));")
    sql.execute("DELETE FROM user;")

    sql.execute("DROP TABLE IF EXISTS notes;")
    sql.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), note VARCHAR(512), shared INTEGER, notepassword NCHAR(256));")
    sql.execute("DELETE FROM notes;")
    db.commit()

    app.run("0.0.0.0", port=5000, ssl_context=(
        './SSL/server.crt', './SSL/server.key'))
