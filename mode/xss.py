# !/usr/bin/env python3
# @author:...
from async_timeout import timeout


try: 
    import os
    import logging
    import requests
    import core.config as config
    import core.colors as color
    
    try:
        from bs4 import BeautifulSoup
    except ImportError as e:
        print(color.falta+" BeautifullSoup não está instalada...");
        print(color.info+" Instalando o módulo BeautifullSoup...")
        os.system("apt-get install python3-bs4 | pip install beautifulsoup4")
        print(color.info+' BeautifullSoup instalado')
        quit()
        
    def xssStrike(url, timeout, verbose):
        timeout = config.REQUEST_TIMEOUT
        header = config.HEADERS
        
        #abrir uma try aqui que vai pegar as enceções da requisição das url
        print("["+color.green+"+"+color.end+"]"+color.end+" Modo de"+color.green+" deteção xss"+ color.end+" passada para o alvo "+color.cian+url)
        
        
            
        
except ImportError as e:
    print("Erro de importação")
    quit()

