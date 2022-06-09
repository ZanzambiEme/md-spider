# !/usr/bin/env python3
'''
handle command line arguments
'''

from core.utils import exitTheProgram
from mode.plugin.models import argumentError, dnsError, noTargetFound
from datetime import datetime
from core import colors as color
import argparse

def commandLineArguments():
            parse = argparse.ArgumentParser(description='Detetor de Vulnerabilidades web', prog='spider', epilog='CopyRight Spider Developers')
            parse.add_argument('-u', '--url', metavar='', help='alvo e.g. http://www.site.com/vuln.php ou http://www.site.com/vuln.php?id=1- para alvos injeção sql', dest='target')
            #parse.add_argument('-d', '--data', metavar='', help='Payloads a serem enviados. (eg: "id=1")', dest='payload')
            #parse.add_argument('-p', '--port', metavar='', help='Porta do servidor proxy eg: python3 spider -u alvo -sql --proxy 0.0.0.0 -p 8080)', dest='proxy_port')
            #parse.add_argument('-P', '--proxy', metavar='', help='Servidor proxy (eg: python3 spider -u alvo -sql --proxy 0.0.0.0)', dest='proxy_server')
            #parse.add_argument('-c', '--cookie', metavar='', help='Cookies de sessão http a serem usados (e.g: python3 spider -u alvo -sql --proxy 0.0.0.0 -p 8080 -c a8d127e...)', dest='cookie')
            parse.add_argument('-t', '--timeout', metavar='', help='Define o tempo da requisição (e.g: python3 spider -u alvo -t 4 -sql -- proxy 0.0.0.0 -p 8080 -c a8d127e...)', dest='timeout')
            parse.add_argument('-r', '--response', metavar='',  help='Interação da página em relação aos dados do login inseridos. (python3 spider -u alvo -sql --response "usuario ou login inválido")', dest='response')
            parse.add_argument('-v', '--verbose', help='Habilita o modo Verbose, mostrando processos a serem executados em background', action='store_true') 
            parse.add_argument('-H', '--http_enum', help='Enumera cabeçalhos e verbos http vulneráveis', action='store_true') 
            #parse.add_argument('-T', '--tamper', help='Usando esse flag, o Spider tentará usar mecanismos de modo a ultrapassar os WAF', action='store_true')
            parse.add_argument('-S', '--shell', help='Usando esse flag, o Spider tentará retornar ums uma shell sql', action='store_true')
            parse.add_argument('-d', '--dump_tables', help='Usando esse flag, o Spider irá enumerar do servidor do alvo todos oos bancos de dados bem como as suas tabelas', action='store_true')
            parse.add_argument('-dT', '--dump_all', help='Usando esse flag, o Spider irá enumerar todas as tables que o alvo contêm', action='store_true')
            parse.add_argument('--auth_bypass', help='O Spider irá tentaar fazer um ultrapassagem de autenticação no alo', action='store_true')
            parse.add_argument('-log', help='visualização dos logs do web spider ', action='store_true')
            parse.add_argument('-logj', help='visualização dos logs Json do web spider ', action='store_true')
            mode = parse.add_argument_group(title='Modos de Detenção')  ## modos de de detenção []
            #mode.add_argument('-html', help='injeção html (e.g: python3 spider -u alvo -t 4 -html --proxy 0.0.0.0 )',action='store_true',dest='html')
            mode.add_argument('-xml', help='Habilita o modo de detenção xml (e.g: python3 spider -u alvo -t 4 -xml --proxy 0.0.0.0 ) ', action='store_true', dest='xml')
            #mode.add_argument('-sh', help='Injeção de sessão (e.g: python3 spider -u alvo -t 4 -sh --proxy 0.0.0.0 )', action='store_true', dest='sh')
            mode.add_argument('-sql', help='Habilita o modo de Detenção e injeção sql (e.g: python3 spider -u alvo -t 4 -sql --proxy 0.0.0.0 )', action='store_true', dest='sql')
            #mode.add_argument('-os', help='injeção  os (e.g: python3 spider -u alvo -t 4 -os --proxy 0.0.0.0 )', action='store_true', dest='os')
            mode.add_argument('-xss',help='Habilita o modo de detenção Cross-Site Srcipting (xss) (e.g: python3 spider -u alvo -t 4 -xss --proxy 0.0.0.0 )', action='store_true', dest='xss')
            mode.add_argument('-ma', help='Ataque de Atribuição em Massa (e.g: python3 spider -u alvo -t 4 -ma --proxy 0.0.0.0 ) ', action='store_true', dest='ma')
            #mode.add_argument('-ma', help='Ataque de Atribuição em Massa (e.g: python3 spider -u alvo -t 4 -ma --proxy 0.0.0.0 ) ', action='store_true', dest='ma')
            other = parse.add_argument_group( title='Outras Vulnerabilidades...')
            other.add_argument('--jquery', help='Verificar por potenciais falhas na versão do jquery', action='store_true', dest='jquery')
            other.add_argument('--wordpress', help='Verificar versões vulneráveis do plugins Wordpress', action='store_true', dest='wordpress')
            other.add_argument('--laravel', help='Verificar versões vulneráveis no Laravel no alvo', action='store_true', dest='laravel')
            other.add_argument('--nodeJs', help='Verificar versões vulneráveis no Laravel no alvo nodeJs no alvo passado', action='store_true', dest='nodejs')
            args    = parse.parse_args()
            #PAYLOADS  = args.payload
            TIMOUT    = args.timeout
            VERBOSE   = args.verbose
            RESPONSE  = args.response
            DUMP_TABLES      = args.dump_tables
            DUMP_ALL = args.dump_all
            AUTH_BYPASS = args.auth_bypass
            SPIDER_LOG = args.log
            SPIDER_LOGJ = args.logj
            #COOKIE    = args.cookie
            #TAMPER    = args.tamper
            SHELL     = args.shell
            HTTP_ENUMERATION = args.http_enum
            #PROXY_PORT   = args.proxy_port
            #PROXY_SERVER = args.proxy_server
            TARGET_URL       = args.target
            #HTML_INJECTION   = args.html
            XML_INJECTION    = args.xml
            SQL_INJECTION    = args.sql
            #OS_INJECTION     = args.os
            XSS              = args.xss
            #SH_INJECTION     = args.sh
            MASS_ACTACK      = args.ma
            JQUERY      = args.jquery               
            WORDPRESS   = args.wordpress            
            LARAVEL     = args.laravel              
            NODEJS      = args.nodejs               
            if SPIDER_LOG:
                import os
                os.system("nano ./logs/WebSpider.log")
                exitTheProgram()
            if SPIDER_LOGJ:
                import os
                os.system("nano ./logs/logs.json")
                exitTheProgram()    
            if TARGET_URL:
                import core.utils as utilsfucntions
                from core.config import ACTION_VALIDATE
                ## importação de modos de ação
                from mode.xss import _xss
                from mode.sql import _sqlInjection
                from mode.xxe import  _xxe
                from mode.ma import _ma
                if(utilsfucntions.urlValidator(TARGET_URL) == True):
                    if XML_INJECTION:
                        _xxe(TARGET_URL,'', '', VERBOSE, '', '', HTTP_ENUMERATION)
                        ACTION_VALIDATE = True
                    if SQL_INJECTION:
                        _sqlInjection(TARGET_URL, RESPONSE, SHELL, DUMP_TABLES, DUMP_ALL, AUTH_BYPASS)                   
                        ACTION_VALIDATE = True
                    if XSS:
                        _xss(TARGET_URL, TIMOUT, VERBOSE, HTTP_ENUMERATION)
                        ACTION_VALIDATE = True
                    if MASS_ACTACK:
                        _ma(TARGET_URL)
                        ACTION_VALIDATE = True
                    if ACTION_VALIDATE == False:
                        argumentError()
                else: 
                    dnsError(target=TARGET_URL)
            else:
                noTargetFound()