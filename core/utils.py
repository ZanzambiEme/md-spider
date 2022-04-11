# !/usr/bin/env python3

from fileinput import filename
import logging
import re

import requests

def logginStore():
    try:
        import core.colors as color
        
        logging.basicConfig(filename='./logs/WebSpider.log', format='%(levelname)s [%(asctime)s] %(name)s %(process)d %(pathname)s [%(message)s]', level=logging.DEBUG, encoding='utf-8')
        
    except ImportError as e:
        print(color.bad+' erro em importar % '.format(e))
        
def urlValidator(url):
    if 'http://' in url[:7]:
        return True
    elif 'https://' in url[:8]:
        return True
    if 'www' in url[:3]:
        return True
    else:
        return False
## Calcula o tempo de Requisição da página, para o uso de testes de ataques slqi baseada no tempo
## função usual pra testaar injeções sql baseados no tempo -jitter
def avaregeTime(url):
    i = 0
    values = []
    while i < 1: ## na condição terei de usar um número com base na quantidade de payloads a ser submetida no alvo
        req = requests.get(url)
        values.append(int(req.elapsed.total_seconds()))
        i = i + 1
    media_requisicao = sum(values) / float(len(values))
    return media_requisicao
