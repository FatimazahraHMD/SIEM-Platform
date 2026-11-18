"""
Application de démonstration XSS
"""
from flask import Flask, request, redirect, url_for, render_template, g
import sqlite3
import os
import secrets

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "comments.db")


@app.before_request
def ensure_session_cookie():
    if not request.cookies.get("session_id"):
        g.new_session_id = secrets.token_hex(8)


@app.after_request
def set_session_cookie(response):
    if hasattr(g, "new_session_id"):
        response.set_cookie("session_id", g.new_session_id)
    return response


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                message TEXT NOT NULL
            )
            """
        )
        db.commit()


@app.route("/", methods=["GET"])
def index():
    db = get_db()
    comments = db.execute(
        "SELECT id, name, message FROM comments ORDER BY id DESC"
    ).fetchall()
    return render_template("index.html", comments=comments)


@app.route("/post", methods=["POST"])
def post_comment():
    name = request.form.get("name", "").strip()
    message = request.form.get("message", "").strip()
    if name and message:
        db = get_db()
        db.execute(
            "INSERT INTO comments (name, message) VALUES (?, ?)",
            (name, message),
        )
        db.commit()
    return redirect(url_for("index"))


@app.route("/reset", methods=["POST"])
def reset_comments():
    """Vide la table des commentaires"""
    db = get_db()
    db.execute("DELETE FROM comments")
    db.commit()
    return redirect(url_for("index"))


@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    return render_template("search.html", q=q)


@app.route("/welcome", methods=["GET"])
def welcome():
    return render_template("welcome.html")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
