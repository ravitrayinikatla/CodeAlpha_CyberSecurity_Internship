import sqlite3
import hashlib
import os
from flask import Flask, request, session, redirect, render_template_string

app = Flask(__name__)

# [VULN-1] Hardcoded secret key — trivially guessable
app.secret_key = "supersecret123"

# [VULN-2] Hardcoded admin credentials in source code
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

# [VULN-3] Debug mode ON — exposes interactive debugger in production
app.config["DEBUG"] = True

# ---------- Database setup ----------

def get_db():
    conn = sqlite3.connect("users.db")
    return conn

def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    # [VULN-4] Passwords stored as unsalted MD5 hashes
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', ?, 'admin')",
        (hashlib.md5(b"admin123").hexdigest(),)
    )
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (2, 'alice', ?, 'user')",
        (hashlib.md5(b"password").hexdigest(),)
    )
    conn.commit()
    conn.close()

# ---------- Routes ----------

LOGIN_TEMPLATE = """
<html><body>
<h2>Login</h2>
{% if error %}
<!-- [VULN-5] Reflected XSS — error message echoed without escaping -->
<p style="color:red">Error: {{ error | safe }}</p>
{% endif %}
<form method="POST">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
</body></html>
"""

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # [VULN-6] SQL Injection — string-concatenated query
        conn = get_db()
        query = (
            "SELECT * FROM users WHERE username = '" + username +
            "' AND password = '" + hashlib.md5(password.encode()).hexdigest() + "'"
        )
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            session["user"] = user[1]
            session["role"] = user[3]
            return redirect("/dashboard")
        else:
            # Echo raw input back into the page — XSS vector
            error = f"Invalid login for user: {username}"

    return render_template_string(LOGIN_TEMPLATE, error=error)


@app.route("/dashboard")
def dashboard():
    # [VULN-7] Missing authentication check — any URL visitor sees this
    user = session.get("user", "Guest")
    return f"<h1>Welcome, {user}!</h1><a href='/admin'>Admin Panel</a>"


@app.route("/admin")
def admin():
    # [VULN-8] Missing authorization check — no role verification
    conn = get_db()
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    rows = "".join(f"<tr><td>{u[0]}</td><td>{u[1]}</td><td>{u[2]}</td></tr>" for u in users)
    return f"<h1>Admin Panel</h1><table border=1>{rows}</table>"


UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            # [VULN-9] Insecure file upload — no type/extension validation
            save_path = os.path.join(UPLOAD_DIR, f.filename)
            f.save(save_path)
            return f"Saved to {save_path}"
    return """
    <form method="POST" enctype="multipart/form-data">
      <input type="file" name="file">
      <input type="submit" value="Upload">
    </form>
    """


if __name__ == "__main__":
    init_db()
    # [VULN-10] Running on all interfaces (0.0.0.0) in debug mode
    app.run(host="0.0.0.0", port=5000, debug=True)

