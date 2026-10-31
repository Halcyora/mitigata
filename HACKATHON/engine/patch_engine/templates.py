from __future__ import annotations

from typing import Final

PATCH_TEMPLATES: Final[dict[str, str]] = {
    "sql_injection": """\
# SQL injection — bind values instead of concatenating them into SQL.
# SQLite example; use the driver's parameter placeholder syntax for other databases.
cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
""",
    "xss": """\
# XSS — render untrusted values as template data so the framework can encode them.
# Flask/Jinja example; keep autoescaping enabled and do not mark user data safe.
return render_template("profile.html", display_name=user_input)
""",
    "command_injection": """\
# Command injection — avoid a shell and pass each argument separately.
# Use a fixed executable and validate the argument against the expected domain.
result = subprocess.run(
    ["/usr/bin/grep", "--", query, "/var/log/app.log"],
    capture_output=True,
    text=True,
    check=False,
    timeout=5,
)
""",
    "weak_hash": """\
# Weak password hash — use a password-hashing algorithm with a work factor.
# Example with bcrypt; verify passwords with bcrypt.checkpw.
password_hash = bcrypt.hashpw(
    password.encode("utf-8"),
    bcrypt.gensalt(),
)
""",
    "jwt_weak_secret": """\
# JWT — require a high-entropy secret from configuration and pin the algorithm.
# Validate issuer/audience values appropriate to this application.
claims = jwt.decode(
    token,
    os.environ["JWT_SECRET"],
    algorithms=["HS256"],
    issuer=EXPECTED_ISSUER,
    audience=EXPECTED_AUDIENCE,
)
""",
    "ssti": """\
# SSTI — keep templates application-controlled; pass user input only as data.
# Flask/Jinja example: profile.html must be a static, trusted template.
return render_template("profile.html", display_name=user_input)
""",
    "eval_injection": """\
# Eval injection — remove dynamic evaluation; parse only the required data format.
# For numeric expressions, use a dedicated parser with an allowlisted AST grammar.
value = parse_allowed_expression(user_input)
""",
    "insecure_deserialisation": """\
# Insecure deserialisation — use a data-only format and validate its schema.
payload = json.loads(data)
session = SessionSchema.model_validate(payload)
""",
}

_CWE_TO_SINK: Final[dict[str, str]] = {
    "CWE-89": "sql_injection",
    "CWE-79": "xss",
    "CWE-78": "command_injection",
    "CWE-916": "weak_hash",
    "CWE-347": "jwt_weak_secret",
    "CWE-94": "ssti",
    "CWE-95": "eval_injection",
    "CWE-502": "insecure_deserialisation",
}


def get_template_patch(sink_type: str) -> str | None:
    """Return a deterministic remediation snippet for a supported sink type."""
    return PATCH_TEMPLATES.get(sink_type)


def default_fix_template(cwe_id: str) -> str:
    """Return a deterministic remediation hint, falling back for unknown CWEs."""
    normalized = cwe_id.strip().upper()
    sink_type = _CWE_TO_SINK.get(normalized)
    if sink_type is None:
        return (
            f"Review the sink for {normalized or 'the reported CWE'}; validate and "
            "constrain untrusted input at the sink using the relevant library's "
            "documented safe API."
        )
    return PATCH_TEMPLATES[sink_type]
