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
            
            import re
            import requests
            
            print("["+color.green+"!"+color.end+"]"+color.end+" Modo de"+color.orange+" deteção injeção sql"+ color.end+" passada para o alvo "+color.orange+target_url+color.end)
            
            
            print("["+color.green+"+"+color.end+"] Calculando o tempo média da requisição...") 
            print("["+color.green+"+"+color.end+"] Tempo média da requisição: "+color.cian, avaregeTime(target_url), color.end)
            
            ## pensei assim, primeiro testar o ataque de ijenção sql inferencial baseada no tempo, dai se não resultar, tentar inferencial boleana
          
            ## filtrando a variável url id do alvo passado
            try:
                print("["+color.green+"+"+color.end+"] Filtrando a variável url 'id'...") 
                para = re.compile('(id=)\w+')
                if para.search(target_url):
                    '''
                    Faz o teste sqli no parâmetro GET (id) assim como filtrado 👇👇👇👇👇👇
                    '''
                    splited_para = para.search(target_url).group()
                    if 'id' in splited_para:
                        print("["+color.green+"+"+color.end+"] Variável url 'id' filtrado") 
                        print("["+color.green+"+"+color.end+"] Testando o alvo com injeção sql inferencial...") 
                        ## faz os testes sqli diretamente???
                        try:
                            with open('./mode/payload/sql-payloads', 'r') as payloads:
                                for payloads_lines in payloads:
                                    exploited_target_url = target_url.replace(splited_para, 'id='+payloads_lines)
                                    requesicao = requests.post(url=exploited_target_url) ## falta configurar o proxxy, timout e mais sei la oque
                                    print("Código de status da requisição: ", format(requesicao.status_code))
                                    ## como verificar que a injeção teve sucesso???
                        except FileNotFoundError as e:
                            print(color.info_1+color.red_0+color.info_2+" Erro: arquivo "+color.red+" sql-payloads"+color.orange+" não foi encontrado"+color.end)
                            quit()
                else:
                    '''
                    Faz o teste sqli nos campos de formulários filtrados 👇👇👇👇👇👇👇👇👇
                    '''
                    print(color.info_1+color.red_0+color.info_2+" Aviso:"+color.end+color.end+" O alvo não  contêm um parâmetro GET passado('http://www.site.com/artigo.php?id=1')"+color.end)
                    print("["+color.green+"+"+color.end+"] Filtrando formulários...")
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