from __future__ import annotations

import getpass
import sqlite3

from werkzeug.security import generate_password_hash

from wansinn import create_app
from wansinn.core.db import get_db


def main() -> int:
    username = input("Admin-Benutzername [admin]: ").strip() or "admin"
    password = getpass.getpass("Admin-Passwort (mind. 10 Zeichen): ")
    repeat = getpass.getpass("Passwort wiederholen: ")

    if len(username) < 3:
        print("Benutzername muss mindestens 3 Zeichen lang sein.")
        return 1
    if len(password) < 10:
        print("Passwort muss mindestens 10 Zeichen lang sein.")
        return 1
    if password != repeat:
        print("Passwörter stimmen nicht überein.")
        return 1

    app = create_app()
    with app.app_context():
        db = get_db()
        existing = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        if existing:
            print("Es existiert bereits mindestens ein Benutzer. Nutze die Benutzerverwaltung im Webinterface.")
            return 1
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            print("Benutzername existiert bereits.")
            return 1

    print(f"Administrator {username!r} wurde angelegt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
