#! /usr/bin python3 
'''
HANDLE AL WEB SPIDER MESSAGES
'''

from pendulum import datetime
from core import colors as color
from datetime import datetime
from core.utils import exitTheProgram

def platformMessages(platform):
    if platform == "windows":
        print(color.red+"[!][", datetime.now(),"]  Erro: O Web spider não é conpatível com Sistema Operacional%s"%platform+color.end)
        exitTheProgram()
    else:
        print(color.orange+"[!][", datetime.now(),"] %s"%platform+color.end)
def modeBanner(target_url, mode):
    print("["+color.green+"!"+color.end+"]"+color.end+"["+color.admin_side, datetime.now(), color.end+"]  Modo de"+color.orange+" deteção %s"%mode+ color.end+" passada para o alvo "+color.orange+target_url+color.end)
def checkEstability():
    print("["+color.green+"~"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Testando a estabilidade da conexão, pode levar alguns minutos...")
def notStable():
     print(color.orange+"[!][", datetime.now(),"]  Aviso: A sua conexão parece estar instável, recomenda-se que se tenha uma conexão estável."+color.end, end='')
def endingTest():
     print(color.orange+"[!][", datetime.now(),"]  Aviso: Terminando o teste..."+color.end, end='')
def inputError():
    print(color.red+"[!][", datetime.now(),"] Erro: Entrada inválida"+ color.end)
def stableConnection():
    print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Conexão estável ")
def formEnum():
    print("["+color.green+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Enumerando formulários..."+color.end)
    
def noFormFound():
    print(color.orange+"[!][", datetime.now() ,"]  Aviso:  O alvo  não contêm campos onde se possa introduzir dados..."+color.end)
def inputFiltering(position):
    print("["+color.green+"+"+color.end+"]" +color.end+"["+color.admin_side, datetime.now(), color.end+"]  Filtrando os Possíveis campos vulneráveis...."+color.end+"no formulário na posição ["+color.cian, position,color.end+"]")
def creatingParamaters():
    print("["+color.green+"+"+color.end+"]" +color.end+"["+color.admin_side, datetime.now(), color.end+"]  Gerando novos parâmetros...."+color.end)
def targetVulnerable(mode):
     print("["+color.red+"!"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Estado:"+color.admin_side+" Alvo Vulnerável a %s"%mode+color.end)
def targetNotVulnerable(mode):
     print("["+color.green+"!"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Estado: "+color.red+"Alvo Não Vulnerável a %s"%mode+color.end)
def testing():
    print("["+color.green+"+"+color.end+"]"+color.green+color.end+"["+color.admin_side, datetime.now(), color.end+"]  Testando...")
def verboseStatus(lines, status, colorStyle):
    if colorStyle == "red":
        print("["+color.admin_side+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] ["+color.red, status,color.end+"] [PAYLOAD] "+color.end+lines, end=''+color.end)
    else:
        print("["+color.admin_side+"+"+color.end+"]["+color.admin_side, datetime.now(), color.end+"] ["+color.admin_side, status,color.end+"] [PAYLOAD] "+color.end+lines, end=''+color.end)
def endInjection():
    print("["+color.green+"!"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Injenção De Payloads Terminada")
def targetStatus(status, statusColor):
    if statusColor == "red":
        print("["+color.red+"!"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Estado:"+color.red, status,  color.end)
    else:
        print("["+color.red+"!"+color.end+"]["+color.admin_side, datetime.now(), color.end+"]  Estado:"+color.admin_side, status,  color.end)
def WebSpiderExceptions(type):
    if type == "ImportError":
        print(color.red+"\n[!][", datetime.now() ,"] Falha na importação dos Módulos."+color.end)
        exitTheProgram()
    if type == "KeyboardInterrupt":
        print('\n'+color.red+"[!][", datetime.now() ,"] Erro: Interrupção pela parte do usuário"+color.end)
        exitTheProgram()
    if type == "requests.exceptions.RequestException ":
        print(color.red+"[!][", datetime.now() ,"] Erro: alvo Inacessível, verifique a sua ligação à internet ou contacte o  Web master."+color.end)
        exitTheProgram()
    if type =="FileNotFoundError":
        print(color.red+"[!][", datetime.now() ,"] Erro: Arquivo de texto não encontrado"+color.end)
        exitTheProgram()
    if type=="AttributeError":
        print(color.red+"[!][", datetime.now() ,"]  Erro:  O programa não conseguiu processar a atribuição do argumento..."+ color.end)
        exitTheProgram()
def argumentError():
    print(color.red+"[!][", datetime.now() ,"]  Erro: Modo de Ação não detectado, execute"+color.cian+" [compilador] spider [-h] " +color.red+ "para ver os modos a usar com o spider"+color.end)
    exitTheProgram()
def dnsError(target):
    print(color.red+"[!][", datetime.now() ,"]  Erro: Falha na Resolução de DNS, Verifique se há um erro de digitação em "+color.cian+target+color.end) 
    exitTheProgram()
def noTargetFound():
    print(color.red+"[!][", datetime.now() ,"]  Erro: Sem alvo passado, execute" +color.cian+ " [compilador] spider [-h] " +color.red+  "para ver as opões a usar com o spider"+color.end) 
    exitTheProgram()
    
'''Handle sqli messages...'''
def sqli():
    return