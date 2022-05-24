# /usr/bin pyhton3
import os
from core import colors as color
from datetime import datetime
from core.utils import exitTheProgram

def dumpAll(url):
    if "=" in url:
        print("\n["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Inicializando o plugin sqlmap.."+color.end)
        print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Sqlmap inicializado"+color.end)
        os.system("python3 ./mode/plugin/sqlmap/sqlmap.py -u  %s --dump-all " %url)
    else:
        print("["+color.orange+"+][", datetime.now(),"]  Erro: não foi encontrado nenhum parâmetro GET(id) ou algo similar para a execução do teste "+color.end)
    exitTheProgram()     
    
## retorna um shell sql no alvo
def sqlShell(url):
    print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Inicializando o plugin sqlmap.."+color.end)
    print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Sqlmap inicializado"+color.end)
    os.system("python3 ./mode/plugin/sqlmap/sqlmap.py -u  %s --sql-shell " %url)
    exitTheProgram()
    
def dump_tables(url):
    if "=" in url:
        print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Inicializando o plugin sqlmap.."+color.end)
        print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Sqlmap inicializado"+color.end)
        os.system("python3 ./mode/plugin/sqlmap/sqlmap.py -u  %s --dump" %url)
    else:
        print("["+color.orange+"+][", datetime.now(),"]  Erro: não foi encontrado nenhum parâmetro GET(id) ou algo similar para a execução do teste "+color.end)
    exitTheProgram()  
    
 