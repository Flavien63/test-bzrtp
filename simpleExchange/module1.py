# Créé par flavi, le 12/07/2022 en Python 3.7
import sqlite3
import csv

base = sqlite3.connect('test.db')

cursor = base.cursor()

cursor.execute(
"""SELECT * FROM ziduri""")

inf = cursor.fetchall()

print(inf)

base.close()