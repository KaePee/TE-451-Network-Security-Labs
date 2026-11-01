"""Student account creation: CSV import, single add, password resets."""

import csv
import io
import secrets
from dataclasses import dataclass, field

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction

from apps.accounts.models import User

# No 0/O, 1/l/I: these passwords get read off a printed slip.
_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

HEADER_ALIASES = {
    "index_number": {"index_number", "index", "index no", "index_no", "indexnumber",
                     "student_id", "id"},
    "first_name": {"first_name", "firstname", "first name", "other names", "other_names"},
    "last_name": {"last_name", "lastname", "last name", "surname"},
    "email": {"email", "e-mail", "email address"},
    "password": {"password"},
}


def generate_password() -> str:
    groups = ["".join(secrets.choice(_ALPHABET) for _ in range(4)) for _ in range(3)]
    return "-".join(groups)


@dataclass
class ImportResult:
    created: list[dict] = field(default_factory=list)   # rows incl. plaintext password
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _map_header(header: list[str]) -> dict[str, int]:
    mapping = {}
    for i, raw in enumerate(header):
        name = raw.strip().lower()
        for canonical, aliases in HEADER_ALIASES.items():
            if name in aliases and canonical not in mapping:
                mapping[canonical] = i
    return mapping


def parse_and_create(raw: bytes) -> ImportResult:
    """All-or-nothing: if any row has an error, nothing is created."""
    result = ImportResult()
    try:
        text = raw.decode("utf-8-sig")  # Excel adds a BOM
    except UnicodeDecodeError:
        result.errors.append("File is not UTF-8 text. Export it from Excel as 'CSV UTF-8'.")
        return result

    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        result.errors.append("File is empty.")
        return result
    cols = _map_header(rows[0])
    missing = {"index_number", "first_name", "last_name"} - cols.keys()
    if missing:
        result.errors.append(f"Missing column(s): {', '.join(sorted(missing))}. "
                             f"Found: {', '.join(rows[0])}")
        return result

    def cell(row, name):
        i = cols.get(name)
        return row[i].strip() if i is not None and i < len(row) else ""

    existing = set(User.objects.values_list("username", flat=True))
    seen: set[str] = set()
    pending = []
    for lineno, row in enumerate(rows[1:], start=2):
        if not any(c.strip() for c in row):
            continue
        index = cell(row, "index_number")
        first, last = cell(row, "first_name"), cell(row, "last_name")
        if not index or not first or not last:
            result.errors.append(f"Line {lineno}: index number, first and last name are required.")
            continue
        if len(index) > 32:
            result.errors.append(f"Line {lineno}: index number too long.")
            continue
        if index in seen:
            result.errors.append(f"Line {lineno}: {index} appears twice in the file.")
            continue
        seen.add(index)
        if index in existing:
            result.skipped.append(index)
            continue
        password = cell(row, "password") or generate_password()
        user = User(username=index, index_number=index, first_name=first[:150],
                    last_name=last[:150], email=cell(row, "email")[:254])
        try:
            validate_password(password, user)
        except ValidationError as e:
            result.errors.append(f"Line {lineno}: weak password ({' '.join(e.messages)})")
            continue
        user.set_password(password)
        pending.append((user, password))

    if result.errors:
        return result

    with transaction.atomic():
        User.objects.bulk_create([u for u, _ in pending], batch_size=500)
    result.created = [{"index_number": u.index_number, "first_name": u.first_name,
                       "last_name": u.last_name, "password": pw} for u, pw in pending]
    return result


def create_student(index_number, first_name, last_name, email="") -> tuple[User, str]:
    password = generate_password()
    user = User(username=index_number, index_number=index_number, first_name=first_name,
                last_name=last_name, email=email)
    user.set_password(password)
    user.save()
    return user, password


def reset_password(user: User) -> str:
    password = generate_password()
    user.set_password(password)
    user.must_change_password = True
    user.save(update_fields=["password", "must_change_password"])
    return password
