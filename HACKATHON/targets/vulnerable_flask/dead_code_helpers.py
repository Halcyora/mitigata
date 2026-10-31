import os
import pickle
import sqlite3

from flask import redirect, render_template_string


def _legacy_export_users(db_path: str, filter_str: str):
    """DEPRECATED. CWE-89 — raw SQL string concatenation."""
    conn = sqlite3.connect(db_path)
    result = conn.execute(
        "SELECT * FROM users WHERE name='" + filter_str + "'"
    ).fetchall()
    conn.close()
    return result


def _legacy_run_report(cmd: str):
    """DEPRECATED. CWE-78 — command injection via shell execution."""
    return os.popen("generate_report.sh " + cmd).read()


def _legacy_deserialise_session(data: bytes):
    """DEPRECATED. CWE-502 — unsafe pickle deserialisation."""
    return pickle.loads(data)


def _legacy_eval_formula(expr: str):
    """DEPRECATED. CWE-95 — eval injection."""
    return eval(expr)


def _legacy_template_render(user_input: str):
    """DEPRECATED. CWE-94 — server-side template injection."""
    return render_template_string(user_input)


def _legacy_sql_report(conn, username: str):
    """DEPRECATED. CWE-89 — SQL built from user data via f-string."""
    return conn.execute(f"SELECT * FROM orders WHERE user='{username}'").fetchall()


def _legacy_render_xss(user_input: str):
    """DEPRECATED. CWE-79 — reflected XSS via unescaped output."""
    return f"<div>{user_input}</div>"


def _legacy_path_read(path: str):
    """DEPRECATED. CWE-22 — path traversal via user-controlled file path."""
    return open("/tmp/" + path, "r", encoding="utf-8").read()


def _legacy_redirect(next_url: str):
    """DEPRECATED. CWE-601 — open redirect via unsanitized URL to redirect."""
    return redirect(next_url)
