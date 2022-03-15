# Web Spider 

    Web Spider é uma ferramnenta de detenção de falhas em Aplicasções Web, que está sendo desenvolvido pelos os Estudantes finalista do curso de Gestão de Redes E Sistemas Informáticos da Instituição Politécnico Médio do Kikolo 3096- São José. Ela detecta dentre as demais, as vulnerabilidades que ao longo da História da Internet, vem sido considerado em mais larga escala em releçlão à outras. Dentre elas: XSS, Injeção Sql, Injeção Iframe, Atribuição em Massa, Injeção de Html, Injeção de Sessão, entre outras...

    É uma Aplicação baseada em terminal, isso quer dizer que o usuário deve no mínino estar familiarizado com linhas de comandos para o melhor uso do aplicativo, e para piorar ainda, o aplicativo só é compatível com sistemas Unix, isso quer dizer que usuários que usam outros sistemas tais como Mac OS, Google OS e Windows, talvez estejam incapacitados em usar o programa...

    O programa está sendo desenvolvido toda ela(até nesse momento) em python3, usando a Programação estrutural Baseando em Módulos, e até ao momento, ela já conta com a deteção de falha Cross Site Scripting (XSS), Injeção Sql, Falha de Atribuição em Massa e Injeção de sessão ou Session Mismanegement....

    Actualmente ele se encontra alocado originalmente no repositório https://github.com/zanzambieme/md-spider.git, onde diaramente se tem comitado as mais recentes actualização do seu código

    O objecto final desse projecto é torna lo uma aplicação tão bom em detetar falhas web quanto outras aplicação existentes na comunidade Cybernética, por isso lhe pedimos ajuda no desenvolvimento deste aplicativo, mas o código só será liberado após o trabalho for defendendido na Intituição mencionada acima, após isso, os demais que desejarem dar as sua contribuições pra o desenvolvemento e melhoramento do aplicativo poderão entrar no repositório acima, clonar e dai trabalhar nele no conforto da sua casa...

## Requisitos 
    
    Como mencionado antes, o Projecto só roda em condições em SISTEMAS UNIX, não sendo compatível com os demais, também só é compatível com o compilador >= PYTHON3, e isto devido a acentuações que e condições de codificação e estilo da escrita de código, também exige a instalação de alguns módulos extras, tais como o BeautifullSoup, os, platform, requests, logging, argparse, random, json,  caso a sua distribuição ainda não o tenha, caso o seu distros já o tenha, então a única coisa a fazer é dar um *git clone [Repositóro do Web Spider] https://github.com/zanzambieme/md-spider.git, acessar a pasta md-spider, dai rodar ela com o seguinte comando - [python3 spider -h] _com esse comando, estou pedindo que se execute o programa spider usando o compilador python3 mostrando a tela de ajuda, assim como indicado pela a flag -h(Help ou ajuda em português).

### Flags 

    As Flags disponíveis até ao momento são essas conforme listado no comando acima:

 /$$      /$$           /$$                                 /$$       /$$                    
| $$  /$ | $$          | $$                                |__/      | $$                    
| $$ /$$$| $$  /$$$$$$ | $$$$$$$         /$$$$$$$  /$$$$$$  /$$  /$$$$$$$  /$$$$$$   /$$$$$$ 
| $$/$$ $$ $$ /$$__  $$| $$__  $$       /$$_____/ /$$__  $$| $$ /$$__  $$ /$$__  $$ /$$__  $$
| $$$$_  $$$$| $$$$$$$$| $$  \ $$      |  $$$$$$ | $$  \ $$| $$| $$  | $$| $$$$$$$$| $$  \__/
| $$$/ \  $$$| $$_____/| $$  | $$       \____  $$| $$  | $$| $$| $$  | $$| $$_____/| $$      
| $$/   \  $$|  $$$$$$$| $$$$$$$/       /$$$$$$$/| $$$$$$$/| $$|  $$$$$$$|  $$$$$$$| $$      
|__/     \__/ \_______/|_______/       |_______/ | $$____/ |__/ \_______/ \_______/|__/      
                                                 | $$                                        
                                                 | $$                                        
                                                 |__/  v0.1

usage: spider [-h] [-t] [-d] [-c] [-v] [-u] [-html] [-iframe] [-sh] [-sql] [-os] [-xss] [-http] [-ma]

Detetor de Vulnerabilidades web

optional arguments:
  -h, --help  show this help message and exit
  -t          Tempo de Requisição http
  -d          Payloads a serem enviados. (eg: "id=1")
  -c          Cookies http a serem usados (eg: PHPSESSID=a8d127e...)
  -v          Verbose

Argumentos obrigatórios:
  -u          alvo e.g. http://www.site.com/vuln.php ou http://www.site.com/vuln.php?id=1-pra alvos injeção sql

Injeções:
  -html       injeção html
  -iframe     injeção iframe
  -sh         Injeção de sessão
  -sql        injeção sql
  -os         injeção os
  -xss        Cross-Site Srcipting (xss)

Outras Vulnerabilidades...:
  -http       Poluição dos Parâmetros HTTP
  -ma         Ataque de Atribuição em Massa

CopyRight Spider Developers

#### Exemplos 
#### xss
    Bom, tenho uma aplicação web e desejo saber se ele é ou não vulnerável a ataques XSS, para isso o comando alistado abaixo serve:

        pyhton3 spider -u https://alvo.com/pagina-vulneravel -xss -v 

        A flag -u indica pro spider que desejo passar alvo em formato url, e como já podem notar, é uma flag obrigatório, -xss diz pra o programa testar a vulnerabilidade xss contra a página indica em -u, e -v diz pra o programa mostrar os processis que estão sendo feito nos bastidores, essa é uma das minhas favoritas! :-)

        As requisições http tem um tempo estalecido de 10 segundo, portanto desse geito, o programa irá requisitar pelo o alvo durante esse periodo de tempo, isso pode se mudar utilizando a flag -t, que estabelece o tempo de conexão ou requesição..

        python3 spider -u https://alvo.com/pagina-vulneravel -xss -t 5 -v

    O procedimento será o mesmo para os demais móddos de ação, ou vulnerabilidades, caso não saibas quais ou qual vulnerabilidade desejas especificamente no momento, podes simplesmente passar o seguinte comando na linha de comando e pronto:

        python3 spider -u https://alvo.com/pagina-que-desejas -a

        Com esse comando, o spider vai fazer uma varredura na página passada porcurando pela possível falha no intevalo de tempo considerável com base nos tipos e quantidade de falhas que lhe foi instruido... algo que não recomendo não! (Se for num teste de penetração, podes crer que vais perder o Emprego!)

    O spider por padrão aceita o reidirecionamento de terminais, pra quando nbão queres sujar tanto o terminal, então escreva a linha de comando e reidireciona pra um arquivo de texto ou talvez banco de dados, dependendo de si, um exemplo disso pode se ver abaixo:

            python3 spider -t 5 -u https://alvo.com/pagina-que-desejas -v >> arquivo-texto.txt

            --- fazer o comit

#### injeção sql





