# scripts/migrate.py
import sqlite3, datetime

DB = "database.db"
con = sqlite3.connect(DB)
cur = con.cursor()

def has_col(table, col):
    cur.execute(f"PRAGMA table_info({table});")
    return any(r[1] == col for r in cur.fetchall())

changed = False

# 1) email column
if not has_col("user", "email"):
    cur.execute("ALTER TABLE user ADD COLUMN email TEXT;")
    changed = True

# 2) role column
if not has_col("user", "role"):
    cur.execute("ALTER TABLE user ADD COLUMN role TEXT NOT NULL DEFAULT 'user';")
    changed = True

# 3) created_at column
if not has_col("user", "created_at"):
    cur.execute("ALTER TABLE user ADD COLUMN created_at TEXT;")
    cur.execute(
        "UPDATE user SET created_at=? WHERE created_at IS NULL;",
        (datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),)
    )
    changed = True

# 4) unique indexes
cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_user_username ON user(username);")
cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_user_email ON user(email);")

con.commit()
con.close()
print("Migration complete. Changed =", changed)