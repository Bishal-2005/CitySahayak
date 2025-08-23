import sqlite3

# Database connect
conn = sqlite3.connect('citysahayak.db')
cursor = conn.cursor()

# Data fetch
cursor.execute("SELECT id, title, location, image FROM incident")
rows = cursor.fetchall()

# Print karo
for row in rows:
    print(row)

conn.close()
