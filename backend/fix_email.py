import sqlite3
conn = sqlite3.connect('ids.db')
c = conn.cursor()
c.execute("UPDATE users SET email='admin@ids.example.com' WHERE email='admin@ids.local'")
conn.commit()
print('Rows updated:', c.rowcount)
c.execute('SELECT id, username, email FROM users')
print(c.fetchall())
conn.close()
