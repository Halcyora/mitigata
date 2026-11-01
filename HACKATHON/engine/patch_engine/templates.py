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
    "hardcoded_secret": """\
# Hard-coded secret — load it from a secret manager or environment configuration.
# Rotate the exposed credential; removing it from source does not revoke it.
secret = os.environ["SERVICE_SECRET"]
""",
    "weak_crypto": """\
# Risky cryptography — replace obsolete algorithms with a current, vetted
# algorithm from a maintained cryptography library; preserve compatibility only
# through an explicit migration plan.
""",
    "unsafe_type_conversion": """\
# Unsafe conversion — validate the input type and allowed range at the boundary,
# then use an explicit conversion and handle conversion errors.
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
    "CWE-798": "hardcoded_secret",
    "CWE-327": "weak_crypto",
    "CWE-704": "unsafe_type_conversion",
}


def get_template_patch(sink_type: str) -> str | None:
    """Return a deterministic remediation snippet for a supported sink type."""
    return PATCH_TEMPLATES.get(sink_type)


def resolve_sink_type(sink_type: str, cwe_id: str | None) -> str:
    """Use the explicit sink when supported; otherwise infer only exact CWE mappings."""
    if sink_type in PATCH_TEMPLATES:
        return sink_type
    normalized = (cwe_id or "").strip().upper()
    return _CWE_TO_SINK.get(normalized, sink_type)


def default_fix_template(cwe_id: str, sink_type: str | None = None) -> str:
    """Return deterministic remediation guidance, including unknown classifications."""
    normalized = cwe_id.strip().upper()
    mapped_sink = _CWE_TO_SINK.get(normalized)
    if mapped_sink is None:
        classification = f"scanner sink '{sink_type or 'unknown'}'"
        return (
            f"Review {normalized or 'the reported weakness'} ({classification}) "
            "against the scanner rule "
            "description and affected source. Apply the documented mitigation for "
            "that weakness, preserve intended behavior, and verify the change with "
            "a focused regression check. No automated code diff is available for "
            "this classification."
        )
    return PATCH_TEMPLATES[mapped_sink]
