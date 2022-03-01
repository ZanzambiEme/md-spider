# !/usr/bin/env python3

from email import parser
from matplotlib.pyplot import title

from pandas import describe_option


try:
    
    import os
    import json  
    
    import random
    import logging
    import platform
    import argparse
    import core.colors as color
    from core.utils import logginStore
  
    # Web spider Banner 
    from core.banner import WELCOME_BANNER 
    print('\t'+color.green+random.choice(WELCOME_BANNER).center(10)+color.end)
    
    logginStore()
    
    logging.info('[Start on -{} ]'. format(platform.platform()))
    
    
    system    = platform.system() # system- teste de actualização do comit 
    release   = platform.release()
    version   = platform.version()
    arquitect = platform.machine()
    
    sys_info = {'platform':{'system':system, 'release':release, 'version':version, 'machine':arquitect}}
    json_dic = {}
    
    ''' 
   try:
        with  open('./logs/logs.json', 'a+') as logs_json:
            js = json.dumps([sys_info, json_dic], separators=(',', ':') , sort_keys=True, indent=4)
            logs_json.write(js)
    except FileNotFoundError as e:
        print('Arquivo não encontrado')  #desabilitado por enquanto.... NOTA BEM!
    '''
    
    parse = argparse.ArgumentParser(description='Detetor de Vulnerabilidades web', prog='spider.py', epilog='CopyRight Spider Developers')
    
    parse.add_argument('-t', metavar='', help='Tempo de Requisição http', type=float) 
    parse.add_argument('-w', metavar='', help='payload(wordlist)', dest='payload')
    parse.add_argument('-log', help='Mostrar aquivos de log do Web Spider', action='store_true')
    parse.add_argument('-p',   help = 'Porta do servidor', type = int, default=443, metavar='')
    parse.add_argument('-v',   help='Verbose', action='store_true') 
    
    required_argument = parse.add_argument_group(title='Argumentos obrigatórios')
    required_argument.add_argument('-u', metavar='', help='alvo em formato url', dest='target')
    
    Injection = parse.add_argument_group(title='Injeções')
    Injection.add_argument('-html', help='injeção html',action='store_true',dest='html')
    Injection.add_argument('-iframe', help='injeção  iframe', action='store_true', dest='iframe')
    Injection.add_argument('-sh', help='Injeção de sessão', action='store_true', dest='sh')
    Injection.add_argument('-sql', help='injeção sql', action='store_true', dest='sql')
  
    Injection.add_argument('-os', help='injeção  os', action='store_true', dest='os')
    
    xss = parse.add_argument_group( title='Cross-Site Scripting (XSS)')
    xss.add_argument('-xss',help='Cross-Site Srcipting (xss)', action='store_true', dest='xss')
        
    other = parse.add_argument_group( title='Outras Vulnerabilidades...')
    
    other.add_argument('-http',help='Poluição dos Parâmetros HTTP', action='store_true',dest='http')
    other.add_argument('-maa', help='Ataque de Atribuição em Massa ', action='store_true', dest='maa')
    
    try:
         args    = parse.parse_args()
         
         payload  = args.payload
         timeout  = args.t
         verbose  = args.v
         logfiles = args.log
         
         target_url       = args.target
         html_injection   = args.html
         iframe_injection = args.iframe
         sql_injection    = args.sql
         os_injection     = args.os
         xss_attack       = args.xss
         http_polution    = args.http
         sh_injection     = args.sh
         maa_attack       = args.maa
         
         if verbose:
            print("Mostar os processos a executar")
            logging.info('Escolheu o modo verbose')
         
    except AssertionError as e:
        print(color.red,'Erro na passagem de argumentos', color.end)
        logging.error('Error parsing parameters {} '.format(e))
except ImportError as e:
    print ("Erro na importação do módulo %s". format(e))
    logging.error('Import Module Error {} '.format(e))
    