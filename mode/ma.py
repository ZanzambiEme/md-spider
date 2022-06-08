#!/usr/bin python3 
'''
@
'''
from mode.plugin.models import modeBanner, notStable
from mode.plugin.models import checkEstability
from mode.plugin.models import notStable
from core.utils import avaregeTime
from core.utils import exitTheProgram
from core.config import AVARAGE_TIME_BASED_SQLI
from core.config import NEW_FORM_PARAMETERS
from core.config import  HEADERS
from bs4 import BeautifulSoup
import requests
def _ma(target_url):
    modeBanner(target_url, "Atribuição em Massa")
    from core.utils import checkURLIntegrity
    checkURLIntegrity(target_url)
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
    from mode.plugin.models import formEnum
    formEnum()
    main_requesition = requests.get(url=target_url)
    main_requesition_parsed = BeautifulSoup(main_requesition.content, 'html.parser')
    forms = main_requesition_parsed.find_all('form')
    if forms:
        pass
    else:
        from mode.plugin.models import noFormFound
        noFormFound()
        exitTheProgram()
    from core.utils import formEnum
    user_option = formEnum(form=forms)
    if user_option > - 1: 
        from core.config import INITIAL_FORM_COUNT_VALUE
        for usuario_option in range(INITIAL_FORM_COUNT_VALUE):
            from core.utils import arrayForm
            array_form_return = arrayForm(forms)
            from mode.plugin.models import inputFiltering
            inputFiltering(position=user_option)
            from mode.plugin.models import creatingParamaters
            creatingParamaters()
            input_dic = {}
            form_on_string = str(array_form_return[user_option])
            form_on_string +=NEW_FORM_PARAMETERS
            form_on_string = BeautifulSoup(form_on_string, 'html.parser')
            input_tag = form_on_string.find_all({'input'})
            for input_tag_perc in input_tag:
                input_dic[''] = NEW_FORM_PARAMETERS
                if 'name' in input_tag_perc.attrs:
                    input_dic[input_tag_perc.attrs['name']] = INITIAL_FORM_COUNT_VALUE
            main_request = requests.post(url=target_url,  headers=HEADERS, data=input_dic)#, proxies= core.config.PROXIES)
            main_request_parsed = BeautifulSoup(main_request.content, 'html.parser')   
            if NEW_FORM_PARAMETERS in main_requesition_parsed.text:
                from mode.plugin.models import targetVulnerable
                targetVulnerable(mode="Mass Assigment Attack")
                exitTheProgram()
            else:
                from mode.plugin.models import targetNotVulnerable
                targetNotVulnerable(mode="Mass Assigment Attack")
                exitTheProgram()                        