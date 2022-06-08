# !/usr/bin/env python3
from core import colors as color
from datetime import datetime
import requests
import logging
import re
import os
from core.config import INITIAL_COUNT_VALUE, PYTHON_VERSION
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
            print(color.red+"[!][",datetime.now(),"]   Erro: alvo Inacessível, verifique a sua ligação à internet ou contacte o Web master."+color.end)
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

def exitTheProgram():
    print("<<  "+color.admin_side, datetime.now(), color.end+" - @  Web sipder saindo...>>")
    quit()
       
def errorMessages():
    return  print(color.red+"[",datetime.now(),"]", end='')
    
def checkPythonVersion():
    import sys
    PYVERSION = sys.version.split()[0]
    if PYVERSION >= "3.9":
        pass
    else:
        print(color.red+"[!][", datetime.now(),"]  Erro: versão de python incopatível, o Web Spider só pode ser executado  em versões IGUAL ou MAIOR que 3."+color.end)
        exitTheProgram()
    
def checkURLIntegrity(url):
    print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Testando a integridade do alvo...")
    try:
        req = requests.get(url=url)
    except requests.exceptions.RequestException :
        print(color.red+"[!][", datetime.now() ,"]  Erro: alvo Inacessível, verifique a sua ligação à internet ou contacte o  Web master."+color.end)
        exitTheProgram()
    if req.status_code == 404:
        print(color.red+"[!][", datetime.now(),"]   Erro: não foi possível verificar a integridade do alvo..."+color.end)
        exitTheProgram()
    else:
        print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Alvo intégro")
        pass
    
def formEnum(form):
    form_quant = -1
    array_form = {}
    validation_page = {} 
    for form_perc in form:
        form_quant += 1
        if 'action' in form_perc.attrs:
            validation_page[form_quant] = form_perc['action']      
        array_form[form_quant] = form_perc 
    if form_quant  == 0:
        print("["+color.green+"+"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"]  Foi enumerado [(1)] formulário.")
        pass
    else:
        print("["+color.green+"+"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"]  Foi enumerado [0 -(%s)] formulários." % (form_quant), end='')
        pass
    if form_quant == 0:
        form_quant = 1
        user_option = 0
    else:
        try:
            user_option = int(input(" Qual a posição do formulário que desejas testar?: "))
            pass
        except ValueError as e:
            print(color.red+"[!][", datetime.now() ,"]  Erro: Valor inválido"+color.endswith)
            exitTheProgram()
        if user_option > form_quant or user_option < 0:
            print(color.red+"[!][", datetime.now() ,"]  Erro: Quantidade inválida."+color.end)
            exitTheProgram()
        else:
            pass
    return user_option

def arrayForm(form_array):
    validation_page = {}
    form_quant = -1;
    for form_perc in form_array:
        form_quant += 1
        #if 'action' in form_perc.attrs:
        #   validation_page[form_perc.attrs['action']]        
        form_array[form_quant] = form_perc
    return form_array