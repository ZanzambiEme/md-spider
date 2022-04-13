    # !/usr/bin/env python3
import mysql.connector

mydb = mysql.connector.connect(
    host = "localhost",
    user = "root",
    password=""
)

mycursor = mydb.cursor() ## ponto chave, tudo vaai ser feita com base nisso

mycursor.execute("SHOW DATABASES") ## para executar uma query, basta mudar a string dentro da função execute

for x in mycursor:
    print(x)