# !/usr/bin/env python3
# @author:... Web-spider Developers@2022


from ctypes import sizeof
import random
from os import system
from async_timeout import timeout
from numpy import array
from sympy import pretty
from datetime import datetime

try: 
    import os
    import logging
    import requests
    from core.banner import LINE
    from core.config import INITIAL_FORM_COUNT_VALUE
    from core.config import INITIAL_COUNT_VALUE
    from core import config as config
    from core import colors as color
    from core.utils import urlExplode
    from core.utils import avaregeTime
    from core.utils import exitTheProgram
    
    from datetime import datetime
    
    try:
        from bs4 import BeautifulSoup
    except ImportError as e:
        print(color.falta+"["+color.admin_side, datetime.now(), color.end+"] BeautifullSoup não está instalada...");
        print(color.info+"["+color.admin_side, datetime.now(), color.end+"] Instalando o módulo BeautifullSoup...")
        os.system("sudpo apt-get install python3-bs4 | pip install beautifulsoup4")
        print(color.info+"["+color.admin_side, datetime.now(), color.end+"] BeautifullSoup instalado")
        quit()

        
    def _xss(url, timeout, verbose):
        try:
            
            request_timeout = config.REQUEST_TIMEOUT
            header = config.HEADERS
            validation_page = str()
            unblocked_payloads = {}
        
            input_dic = {}
            
            print("["+color.green+"!"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"] Modo de"+color.orange+" deteção xss"+ color.end+" passada para o alvo "+color.orange+url+color.end)
            try:
                print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Testando a estabilidade da conexão, pode levar alguns minutos...")
                if(avaregeTime(url) >= INITIAL_FORM_COUNT_VALUE):
                    print(color.orange+"[!][", datetime.now(),"] Aviso:"+color.end+color.end+" A sua conexão parece estar instável, recomenda-se que se tenha uma conexão estável."+color.end, end='')
                    ## ainda mostro o jitter aqui só pra comparar com o tempo de teste de injeções sql
                    user_option = str(input(" Deseja continuar? (sim/nao): "))
                    if user_option.lower() == 'sim':
                        pass
                    elif user_option.lower() == 'nao':
                        print(color.orange+"[!][", datetime.now() ,"] Aviso: Terminando o teste..."+color.end, end='')
                        exitTheProgram()
                    else:
                        print(color.red+"[!][", datetime.now() ,"] Erro: Entrada inválida, saindo...")
                        exitTheProgram()
                else:
                    print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Conexão estável ")
                    pass 
                first_request = requests.get(url=url, timeout=request_timeout, headers=header)#proxies=proxy.... desabilitado por enquanto
                first_request_parsed = BeautifulSoup(first_request.content, "html.parser") 
                print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Procurando Formulários...") 
                
                count = INITIAL_COUNT_VALUE
                usuario_entrada = INITIAL_FORM_COUNT_VALUE
                array_form = {}
                form_quant = -1
                validation_page = {} 
                array_form = {}
                succed_payloads = []
                
                form_tag = first_request_parsed.find_all('form') ## filtra a tag form 
                
                if form_tag:
                    pass
                else:
                    print(color.orange+"[!][", datetime.now() ,"] Aviso:  O alvo  não contêm campos onde se possa introduzir dados..."+color.end)     
                    exitTheProgram()
                
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
                        print(color.red+"[!][", datetime.now() ,"] Erro: Valor inválido Saindo do programa..."+color.endswith)
                        exitTheProgram()
                    if user_option > form_quant or user_option < 0:
                        print(color.red+"[!][", datetime.now() ,"] Erro: Quantidade inválida."+color.end)
                        exitTheProgram()
                    else:
                        pass
                    if form_tag:
                        for usuario_option in range(INITIAL_FORM_COUNT_VALUE):
                                    print("["+color.green+"+"+color.end+"]" +color.end+"["+color.admin_side, datetime.now(), color.end+"] Filtrando os Possíveis campos vulneráveis...."+color.end+"no formulário na posição["+color.cian, user_option,color.end+"]")
                                    input_tag = array_form[user_option].find_all({'input'})
                                    print("["+color.green+"+"+color.end+"]"+color.green+color.end+"["+color.admin_side, datetime.now(), color.end+"] Injetando Payloads...")
                                    try:
                                        with open('./mode/payload/xss-payload', 'r') as payload:
                                            if verbose:
                                                pass #print(color.cian+LINE +color.end)
                                            for lines in payload: 
                                                for input_tag_perc in input_tag:
                                                    if "type" in input_tag_perc.attrs:
                                                        if "submit" in input_tag_perc.attrs['type']:
                                                            pass
                                                        else:
                                                            if "checkbox" in input_tag_perc.attrs['type']:
                                                                pass
                                                            else:
                                                                if 'name' in input_tag_perc.attrs:
                                                                    input_dic[input_tag_perc.attrs['name']] = lines
                                                                    config.INPUTS_NUBERS +=1
                                                main_reqsuest = requests.post(url=url, timeout=request_timeout, headers=header, data=input_dic)#, proxies= core.config.PROXIES)
                                                if  lines  in main_reqsuest.text:
                                                    if verbose:
                                                        print("["+color.admin_side+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] ["+color.admin_side+"Viável"+color.end+"] [PAYLOAD] "+color.end+lines, end=''+color.end)
                                                        
                                                        config.TARGET_VULNERABLE = True
                                                        unblocked_payloads[random] = lines
                                                        ## caso o alvo seja vulnerável, da opção pra execução de injeção de um tipo de código malicioso...
                                                        break;
                                                    else:
                                                        unblocked_payloads[random] = lines
                                                        config.TARGET_VULNERABLE = True
                                                        pass
                                                        # adiciona a percentagem do sucesso
                                                if not lines in main_reqsuest.text:
                                                    if verbose:
                                                        print("["+color.red+"-"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] ["+color.red+"Bloqueado"+color.end+"] [PAYLOAD] "+lines,end=''+color.end)
                                                    else:
                                                        pass
                                                        # adiciona a percentagem do secesso
                                                        # cria um aruivo de texto contendo o tipo de payloads que o  sistema alvo deixou passar
                                                with open('./db/unblocked_payloads.txt', 'a+') as unblocked_payloads_list:
                                                    for a, b in unblocked_payloads.items():
                                                        unblocked_payloads_list.write(b)
                                            if verbose:
                                                print()
                                            else:
                                                pass
                                            print("["+color.green+"!"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Injenção De Payloads Terminada")
                                            if config.TARGET_VULNERABLE:
                                                print("["+color.red+"!"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Estado:"+color.admin_side+" Alvo Vulnerável a XSS..."+color.end)
                                                print("...................................................................................................")
                                                print("\t O Web spider encontrou os seguintes pontos vulneráveis no alvo:")
                                                print("\t   Título: XSS :: Payload: %s"%lines)
                                                for index, value in input_dic.items():
                                                    if value == lines:
                                                        print("\t   Variável url: %s" %index)
                                                        exitTheProgram()
                                            else:
                                                print("["+color.green+"!"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] Estado: "+color.red+"Alvo Não Vulnerável a XSS"+color.end)
                                                exitTheProgram()
                                    except FileNotFoundError: 
                                        print(color.red+"[!][", datetime.now() ,"] Erro: Arquivo xss-payload não encontrado"+color.end)
                                        exitTheProgram()                      
                            #else:  
                            #  print(color.info_1+color.red_0+color.info_2+" Aviso:" +color.end+" O formulário está protegida contra Web Scrapers, o valor pra "+color.end+color.cian+"action"+color.orange+" não foi encontrada "+color.end)
                            #  quit()
                    else:
                        print(color.orange+"[!][", datetime.now() ,"] Aviso: O alvo não contêm campos onde se possa introduzir dados...",+color.end)     
                        exitTheProgram()
            except requests.exceptions.RequestException as e:
                print(color.red+"[!][", datetime.now() ,"] Erro: alvo Inacessível, verifique a sua ligação à internet ou contacte o  Web master."+color.end)
                exitTheProgram()
        except KeyboardInterrupt as e:
            print(color.red+"[!][", datetime.now() ,"] Erro: Interrupção pela parte do usuário"+color.end)
            exitTheProgram()
except ImportError as e:
    print(color.red+"[!][", datetime.now() ,"] Erro:  Falha na importação dos Módulos."+color.end)
    exitTheProgram()
    
    ## Difiucldades encontrados
    ## Filtragem da quantidade dos formulários caso  alvo tenha mais  de um
    ## Manipulação dos formulário(Transformar o objeccto Soup em um array)
    ##