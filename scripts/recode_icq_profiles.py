#!/usr/bin/env python3
"""Re-encodes ICQ profile text stored in a legacy code page as UTF-8.

Before the server converted profile text at the protocol boundary, it stored
whatever bytes a client sent. Vintage clients write their ANSI code page, so the
users table holds a mix of UTF-8 and code-page text. This rewrites every profile
value that is not valid UTF-8, and leaves the rest alone.

    python3 scripts/recode_icq_profiles.py oscar.sqlite            # report only
    python3 scripts/recode_icq_profiles.py oscar.sqlite --apply    # write changes

The charset must match the server's ICBM_LEGACY_CHARSET (default cp1251).
"""
import argparse
import sqlite3


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('database')
    parser.add_argument('--charset', default='cp1251')
    parser.add_argument('--apply', action='store_true', help='write the changes; without it only a report is printed')
    args = parser.parse_args()

    db = sqlite3.connect(args.database)
    db.text_factory = bytes
    columns = [
        row[1].decode() for row in db.execute('PRAGMA table_info(users)')
        if row[2].decode().upper() == 'TEXT' and row[1].decode().startswith(('icq_', 'aim_'))
    ]

    changes = []
    skipped = 0
    for row in db.execute(f"SELECT identScreenName, {', '.join(columns)} FROM users"):
        for column, value in zip(columns, row[1:]):
            if not value:
                continue
            try:
                value.decode('utf-8')
                continue
            except UnicodeDecodeError:
                pass
            try:
                changes.append((row[0].decode(), column, value.decode(args.charset)))
            except UnicodeDecodeError:
                skipped += 1
                print(f'skip {row[0].decode()} {column}: not valid {args.charset} either')

    for screen_name, column, text in changes:
        print(f'{screen_name} {column}: {text[:60]!r}')
        if args.apply:
            db.execute(f'UPDATE users SET {column} = ? WHERE identScreenName = ?', (text, screen_name))

    if args.apply:
        db.commit()

    users = len({screen_name for screen_name, _, _ in changes})
    verb = 'recoded' if args.apply else 'to recode'
    print(f'{len(changes)} values of {users} users {verb}, {skipped} skipped')


if __name__ == '__main__':
    main()
