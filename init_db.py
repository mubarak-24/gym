import sqlite3

con = sqlite3.connect("database.db")
cur = con.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS workouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    exercise TEXT,
    reps INTEGER,
    weight REAL,
    date TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

con.commit()
con.close()
print("Table workouts created.")