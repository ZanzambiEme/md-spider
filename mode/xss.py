# !/usr/bin/env python3
''' @author:... Web-spider Developers@2022'''
try: 
    import requests
    from mode.plugin.models import WebSpiderExceptions
    from core.config import INITIAL_FORM_COUNT_VALUE
    from core import config as config
    from core import colors as color
    from core.utils import avaregeTime
    from core.utils import exitTheProgram
    from mode.plugin.models import verboseStatus
    from mode.plugin.models import targetStatus
    from datetime import datetime
    try:
        from bs4 import BeautifulSoup
    except ImportError as e:
        from mode.plugin.models import bs4
        bs4(parameter=" BeautifullSoup não está instalada...")
        bs4(parameter=" Instalando o módulo BeautifullSoup...")
        import os       #
        os.system("sudpo apt-get install python3-bs4 | pip install beautifulsoup4")
        bs4(parameter=" BeautifullSoup instalado")
        pass
    ''' handle xss test'''
    def _xss(url, timeout, verbose, http_enumeration):
        try:
            request_timeout = config.REQUEST_TIMEOUT
            header = config.HEADERS
            unblocked_payloads = {}
            input_dic = {}
            from mode.plugin.models import modeBanner
            modeBanner(target_url=url, mode="XSS")
            from core.utils import checkURLIntegrity 
            checkURLIntegrity(url)                                 
            try:
                from mode.plugin.models import checkEstability
                checkEstability()
                if(avaregeTime(url) >= INITIAL_FORM_COUNT_VALUE):
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
                first_request = requests.get(url=url, timeout=request_timeout, headers=header)#proxies=proxy.... desabilitado por enquanto
                first_request_parsed = BeautifulSoup(first_request.content, "html.parser") 
                if http_enumeration:
                    from mode.plugin.headerEnum import headerEnumeration;'''enumerando e esplorando headers '''
                    headerEnumeration(url)                                                                  
                from mode.plugin.models import formEnum
                formEnum() 
                form_tag = first_request_parsed.find_all('form');'''filtra a tag form '''
                if form_tag:
                    pass
                else:
                    from mode.plugin.models import noFormFound
                    noFormFound()
                    if not http_enumeration:
                        try:
                            print(color.admin_side+"[!][", datetime.now() ,"]"+color.white, end='')
                            user_choise = str(input("  Deseja fazer uma enumeração em cabeçalhos http?(sim/nao):"))
                            if user_choise == "sim":
                                from mode.plugin.headerEnum import headerEnumeration ## enumerando e esplorando headers #
                                headerEnumeration(url)                                                                  
                        except ValueError:
                            inputError()
                            exitTheProgram()
                    exitTheProgram()
                ''' percorre o objecto Soup do formulário, guardando ele no array_form com índices inteiros'''
                from core.utils import formEnum            
                user_option = formEnum(form_tag)           
                if user_option > - 1: 
                        for usuario_option in range(INITIAL_FORM_COUNT_VALUE):
                                    from mode.plugin.models import inputFiltering
                                    inputFiltering(position=user_option)
                                    from core.utils import arrayForm   
                                    array_form_return = arrayForm(form_tag)
                                    input_tag = array_form_return[user_option].find_all({'input'})
                                    from mode.plugin.models import testing
                                    testing()
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
                                                            import random
                                                            verboseStatus(lines=lines,status= "Viável",  colorStyle="admin_site")
                                                            config.TARGET_VULNERABLE = True 
                                                            unblocked_payloads[random] = lines
                                                            break;
                                                        else:
                                                            import random             
                                                            unblocked_payloads[random] = lines
                                                            config.TARGET_VULNERABLE = True
                                                            pass
                                                    if not lines in main_reqsuest.text:
                                                        if verbose:
                                                            verboseStatus(lines=lines,status= "Bloqueado", colorStyle="red")
                                                        else:
                                                            pass
                                                    with open('./db/unblocked_payloads.txt', 'a+') as unblocked_payloads_list:
                                                        for a, b in unblocked_payloads.items():
                                                            unblocked_payloads_list.write(b)
                                                if verbose:
                                                    print()
                                                else:
                                                    pass
                                                from mode.plugin.models import endInjection
                                                endInjection()
                                                if config.TARGET_VULNERABLE:
                                                    targetStatus(status="Alvo Vulnerável a XSS...", statusColor="admin_color")
                                                    from mode.plugin.models import targetRepport
                                                    targetRepport(lines=lines)
                                                    for index, value in input_dic.items():
                                                        if value == lines:
                                                            from mode.plugin.models import httpVariable
                                                            httpVariable(sms=index)
                                                            exitTheProgram()
                                                else:
                                                    targetStatus(status="Alvo Não Vulnerável a XSS", statusColor="red")
                                                    exitTheProgram()
                                    except FileNotFoundError: 
                                        WebSpiderExceptions(type="FileNotFoundError")                      
            except requests.exceptions.RequestException as e:
                WebSpiderExceptions(type="requests.exceptions.RequestException ")
        except KeyboardInterrupt as e:
            WebSpiderExceptions(type="KeyboardInterrupt")
except ImportError as e:
    WebSpiderExceptions(type="ImportError")