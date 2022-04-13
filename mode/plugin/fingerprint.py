# !/usr/bin/env python3

'''
faz um fingerprint no servido, retornando o nome do banco de dados e as suas tabelas
'''

import requests


from core import config
from core import utils

def dbFingerprint(target):
    
    return