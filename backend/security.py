from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import subprocess
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

PASSWORD_HASH_ITERATIONS = int(os.getenv("PASSWORD_HASH_ITERATIONS", "600000"))
SENDMAIL_PATH = os.getenv("SENDMAIL_PATH", "/usr/sbin/sendmail")
MAIL_FROM = os.getenv("MAIL_FROM", "security@vantagecircle.com")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_HASH_ITERATIONS,
    )
    encoded = base64.b64encode(digest).decode("utf-8")
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt}${encoded}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_str, salt, encoded = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations_str),
        )
        expected = base64.b64decode(encoded.encode("utf-8"))
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def generate_session_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_reset_code() -> str:
    return f"{secrets.randbelow(900000) + 100000}"


def send_email(to_email: str, subject: str, body: str) -> None:
    message = EmailMessage()
    message["From"] = MAIL_FROM
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    subprocess.run(
        [SENDMAIL_PATH, "-t", "-oi"],
        input=message.as_bytes(),
        capture_output=True,
        check=True,
    )
