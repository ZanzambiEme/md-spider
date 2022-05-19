#!/usr/bin python3 
from core.utils import color
from datetime import datetime 
from core.utils import exitTheProgram

import requests

def headerEnumeration(url):
    print(color.end+"["+color.green+"!"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"]  Enumerando cabeçalhos HTTP, e verbos HTTP suportáveis pelo o alvo..."+color.end)
    ####################################################
    from core.config import SUPPORTED_HTTP_BYSNESS     #
    ####################################################    
    count = 0;
    for random_http in SUPPORTED_HTTP_BYSNESS:
        try:
            request = requests.get(url=url)
        except requests.exceptions.RequestException:
            print(color.red+"[!][", datetime.now() ,"] Erro: alvo Inacessível, verifique a sua ligação à internet ou contacte o  Web master."+color.end)
            exitTheProgram()
        if random_http in request.headers:
           print("["+color.green+"+"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"]  Cabeçalho parcialmente vulneráveis: "+color.red, random_http, color.end)
           count = 1;
    if count == 0:
      print("["+color.green+"!"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"]  Não foi encontrado nenhum ponto vulnerável nos cabeçahos http")  
    
    