# !/usr/bin/env python3
from socket import socket
import mysql.connector
import socket   

from core.utils import  urlExplode
from core.config import DEFAULT_MYSQL_PORT

def _connectMYSQL(server, db_user, db_password):
    target_db = mysql.connector.connect(host = server, user = db_user ,password= db_password)


def _socket(host):
    #socked_connection = socket.socket.connect(socket.AF_INET, socket.SOCK_STREAM)
    return socket.gethostbyname(urlExplode(host)[2])
    
