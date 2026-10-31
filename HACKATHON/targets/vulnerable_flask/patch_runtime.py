import sys
from pathlib import Path


path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
patches = (
    (
        "hashlib.md5(password).hexdigest()",
        "hashlib.md5(password.encode('utf-8')).hexdigest()",
        1,
    ),
    (
        "User(username, hash_pass)",
        "User(username=username, password=hash_pass)",
        1,
    ),
    (
        "Customer(first_name, last_name, email, username, password, ccn)",
        (
            "Customer(first_name=first_name, last_name=last_name, email=email, "
            "username=username, password=password, ccn=ccn)"
        ),
        1,
    ),
    ("str(e.message)", "str(e)", 2),
    (
        '"{0}".format(auth_token)',
        (
            '"{0}".format(auth_token.decode("ascii") if isinstance(auth_token, bytes) '
            "else auth_token)"
        ),
        1,
    ),
    (
        "yaml.load(y)",
        "yaml.load(y, Loader=yaml.UnsafeLoader)",
        1,
    ),
)

for old, new, expected_count in patches:
    actual_count = source.count(old)
    if actual_count != expected_count:
        raise RuntimeError(
            f"Expected {expected_count} occurrence(s) of {old!r}, found {actual_count}"
        )
    source = source.replace(old, new)

path.write_text(source, encoding="utf-8")
