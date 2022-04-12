# !/usr/bin/env python3
# @author:... Web-spider Developers@2022


from ctypes import sizeof
import random
from os import system
from async_timeout import timeout
from numpy import array
from sympy import pretty


try: 
    import os
    import logging
    import requests
    from core.banner import LINE
    from core.config import INITIAL_FORM_COUNT_VALUE
    from core.config import INITIAL_COUNT_VALUE
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

        
    def _xss(url, timeout, verbose):
        try:
            
            request_timeout = config.REQUEST_TIMEOUT
            header = config.HEADERS
            validation_page = str()
            unblocked_payloads = {}
        
            input_dic = {}
            
            print("["+color.green+"!"+color.end+"]"+color.end+" Modo de"+color.orange+" deteção xss"+ color.end+" passada para o alvo "+color.orange+url+color.end)
            try:
                first_request = requests.get(url=url, timeout=request_timeout, headers=header)#proxies=proxy.... desabilitado por enquanto
                first_request_parsed = BeautifulSoup(first_request.content, "html.parser") 
                print("["+color.green+"+"+color.end+"] Identificando campos pra inserção de dados...") 
                
                count = INITIAL_COUNT_VALUE
                usuario_entrada = INITIAL_FORM_COUNT_VALUE
                array_form = {}
                
                form_tag = first_request_parsed.find_all('form') ## filtra a tag form 
                
                for tag_form_qant in form_tag:  
                    #atribui os valores do objecto Soup na lista array_form, sendo os índices a quantidade dos form encontrados
                    array_form[count] = tag_form_qant 
                    count += INITIAL_FORM_COUNT_VALUE
                print("["+color.green+"+"+color.end+"]"+color.end+" Foi encontrado "+color.cian+format(count)+color.end+ " Formulário /s na página. ", end='') 
                if count == INITIAL_FORM_COUNT_VALUE:
                    usuario_entrada = usuario_entrada
                else:
                    try:   
                        usuario_entrada =  int(input('Quantos desejas testar: '))
                    except ValueError as e:
                        print(color.info_1+color.red_0+color.info_2+" Erro: "+color.red+" Valor inválido"+color.end+" Saindo do programa...")
                        quit()
                if usuario_entrada > count or usuario_entrada < 1 :
                    print(color.info_1+color.red_0+color.info_2+" Erro: "+color.red+"Quantidade "+color.red+"inválida."+color.end+" Saindo do programa...")
                    quit()
                else:
                    if form_tag:
                        for usuario_option in range(INITIAL_COUNT_VALUE, usuario_entrada):
                                    print("\n"+color.cian+LINE +color.end)
                                    print("["+color.green+"+"+color.end+"]" +color.end+" Filtrando os Possíveis campos vulneráveis...."+color.end+ " no formulário na posição "+color.cian,usuario_option,color.end)
                                    input_tag = array_form[usuario_option].find_all({'input'})
                                    print("["+color.green+"+"+color.end+"]"+color.green+color.end+" Injetando Payloads...")
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
                                                if  lines in main_reqsuest.text:
                                                    if verbose:
                                                        print("["+color.green+"ok"+color.end+"] Viável: "+color.end+lines, end=''+color.end)
                                                        config.TARGET_VULNERABLE = True
                                                        unblocked_payloads[random] = lines
                                                    else:
                                                        unblocked_payloads[random] = lines
                                                        config.TARGET_VULNERABLE = True
                                                        pass
                                                        # adiciona a percentagem do sucesso
                                                if not lines in main_reqsuest.text:
                                                    if verbose:
                                                        print("["+color.red+"-"+color.end+"]"+color.green+color.end+" Bloqueado: "+lines,end=''+color.end)
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
                                            print("["+color.green+"!"+color.end+"] Injenção De Payloads Terminada")
                                            if config.TARGET_VULNERABLE:
                                                print("["+color.red+"!"+color.end+"] Estado:"+color.red+" Alvo Vulnerável a XSS..."+color.end+" Veja o relatório dos tipos de payloads não bloqueados em"+color.cian+" /db/unblocked_payloads.txt")
                                            else:
                                                print("["+color.green+"!"+color.end+"] Estado: "+color.green+"Alvo Não Vulnerável a XSS"+color.end)
                                    except FileNotFoundError: 
                                        print(color.info_1+color.red_0+color.info_2+"Erro: Arquivo "+color.red+"xss-payload"+color.orange+" não encontrado"+color.end)
                                        quit()                      
                            #else:  
                            #  print(color.info_1+color.red_0+color.info_2+" Aviso:" +color.end+" O formulário está protegida contra Web Scrapers, o valor pra "+color.end+color.cian+"action"+color.orange+" não foi encontrada "+color.end)
                            #  quit()
                    else:
                        print(color.info_1+color.red_0+color.info_2+" Aviso:"+color.end+color.orange+" O alvo " +color.red+"não contêm campos"+color.orange+" onde se possa introduzir dados...")     
                        quit()
            except requests.exceptions.RequestException as e:
                print(color.info_1+color.red_0+color.info_2+" Erro: "+color.red+"alvo"+color.orange+" Inacessível, verifique a sua ligação à internet ou contacte o"+color.red+" Web master."+color.end)
                quit()
        except KeyboardInterrupt as e:
            print(color.info_1+color.red_0+color.info_2+" Erro: "+color.red+"Interrupção"+color.orange+" pela parte do usuário"+color.red+" Saindo..."+color.end)
            quit()
except ImportError as e:
    print(color.info_1+color.red_0+color.info_2+"Erro: Falha na "+color.red+"importação"+color.orange+" dos Módulos.")
    quit()
    
    ## Difiucldades encontrados
    ## Filtragem da quantidade dos formulários caso  alvo tenha mais  de um
    ## Manipulação dos formulário(Transformar o objeccto Soup em um array)
    ##