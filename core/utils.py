# !/usr/bin/env python3

from fileinput import filename
from core import colors as color
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
## Calcula o tempo de Requisição da página, para o uso de testes de ataques slqi baseada no tempo???
## jitter, testa a estabiidade da conexão da rede local
def avaregeTime(url):
    i = 0
    values = []
    while i < 1:  
        try: 
            req = requests.get(url)
            values.append(int(req.elapsed.total_seconds()))
            i = i + 1
        except requests.exceptions.RequestException as e:
            print(color.info_1+color.red_0+color.info_2+" Erro: "+color.red+"alvo"+color.orange+" Inacessível, verifique a sua ligação à internet ou contacte o"+color.red+" Web master."+color.end)
            quit()
    media_requisicao = sum(values) / float(len(values))
    return media_requisicao

''' divide a url em partes, transformando-o em um array associativo'''
def urlExplode(target):
    url = target.split('/')
    url_exploded = {}
    index = -1
    for teste in url:
        index +=1
        url_exploded[index] = teste
    return url_exploded