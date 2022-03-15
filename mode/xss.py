# !/usr/bin/env python3
# @author:... Web-spider Developers@2022


import random
from os import system
from async_timeout import timeout


try: 
    import os
    import logging
    import requests
    from core.banner import LINE
    from core import config as config
    from core import colors as color
    
    try:
        from bs4 import BeautifulSoup
    except ImportError as e:
        print(color.falta+" BeautifullSoup não está instalada...");
        print(color.info+" Instalando o módulo BeautifullSoup...")
        os.system("sudpo apt-get install python3-bs4 | pip install beautifulsoup4")
        print(color.info+' BeautifullSoup instalado')
        quit()

        
    def xssStrike(url, timeout, verbose):
        request_timeout = config.REQUEST_TIMEOUT
        header = config.HEADERS
        validation_page = str()
        unblocked_payloads = {}
       
        input_dic = {}
        
        print("["+color.green+"!"+color.end+"]"+color.end+" Modo de"+color.orange+" deteção xss"+ color.end+" passada para o alvo "+color.orange+url+color.end)
        try:
            first_request = requests.get(url=url, timeout=request_timeout, headers=header)#proxies=proxy....
            first_request_parsed = BeautifulSoup(first_request.content, "html.parser") 
            print("["+color.green+"+"+color.end+"] Identificando campos pra inserção de dados...") 
            form_tag = first_request_parsed.find_all('form')
            if form_tag:
                print("["+color.green+"+"+color.end+"]" +color.end+" Procurando pela a Página de validação..."+color.end)
                for form_tag_perc in form_tag:
                    if "action" in form_tag_perc.attrs:
                        validation_page = form_tag_perc.attrs['action']
                        print("["+color.green+"+"+color.end+"]" +color.end+" Filtrando os Possíveis campos vulneráveis...."+color.end)
                        input_tag = first_request_parsed.find_all({'input'})
                        print("["+color.green+"+"+color.end+"]"+color.green+color.end+" Injetando Payloads...")
                        try:
                            with open('./mode/payload/xss-payload', 'r') as payload:
                                if verbose:
                                    print(color.cian+LINE +color.end)
                                    pass
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
                                    if  lines in main_reqsuest.text:
                                        if verbose:
                                            print("["+color.green+"ok"+color.end+"] Viável: "+color.end+lines, end=''+color.end)
                                            config.TARGET_VULNERABLE = True
                                            unblocked_payloads[random] = lines
                                        else:
                                            unblocked_payloads[random] = lines
                                            config.TARGET_VULNERABLE = True
                                            pass
                                            # adiciona a percentagem ddo secesso
                                    if not lines in main_reqsuest.text:
                                        if verbose:
                                            print("["+color.red+"-"+color.end+"]"+color.green+color.end+" Bloqueado: "+lines,end=''+color.end)
                                        else:
                                            pass
                                            # adiciona a percentagem do secesso
                                    with open('./db/unblocked_payloads.txt', 'a+') as unblocked_payloads_list:
                                        for a, b in unblocked_payloads.items():
                                            unblocked_payloads_list.write(b)
                                if verbose:
                                    print()
                                else:
                                    pass
                                print("["+color.green+"!"+color.end+"] Injenção De Payloads Terminada")
                                if config.TARGET_VULNERABLE:
                                    print("["+color.red+"!"+color.end+"] Estado:"+color.red+" Alvo Vulnerável a XSS..."+color.end+" Veja o relatório dos tipos de payloads não bloqueados em"+color.cian+" /db/unblocked_payloads.txt")
                                else:
                                    print("["+color.green+"!"+color.end+"] Estado: "+color.green+"Alvo Não Vulnerável a XSS"+color.end)
                        except FileNotFoundError: 
                            print(color.info_1+color.red_0+color.info_2+"Erro: Arquivo "+color.red+"xss-payload"+color.orange+" não encontrado"+color.end)
                            quit()                      
                    else:  
                        print(color.info_1+color.red_0+color.info_2+" Aviso:" +color.red+" Página de validação"+color.end+ color.orange+" não encontrada para a "+color.cian+"<form>"+color.end+" na posição {}")
                        quit()
            else:
                print(color.info_1+color.red_0+color.info_2+" Aviso:"+color.end+color.orange+" O alvo " +color.red+"não contêm campos"+color.orange+" onde se possa introduzir dados...")     
                quit()
        except requests.exceptions.RequestException as e:
            print(color.info_1+color.red_0+color.info_2+" Erro: "+color.red+"alvo"+color.orange+" Inacessível, verifique a sua ligação ou contacte o"+color.red+" Web master."+color.end)
            quit()
except ImportError as e:
    print(color.info_1+color.red_0+color.info_2+"Erro: Falha na "+color.red+"importação"+color.orange+" dos Módulos.")
    quit()
    ## mais ainda tem um bug... caso o alvo tenha mais de uma form na mesma página... falta organizar como as sms serão mostradas....
