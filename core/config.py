#variaveis e Constantes


from http.client import REQUEST_TIMEOUT


ACTION_VALIDATE  = False
REQUEST_TIMEOUT  = 10
INPUTS_NUBERS = 0
TARGET_VULNERABLE = False
INITIAL_FORM_COUNT_VALUE = 1
INITIAL_COUNT_VALUE = 0
AVARAGE_TIME_BASED_SQLI = 1 ## uma conexão é estável quando somente e somente se não houver perdas de pacotes e o valor do jiiter for zero ou próximo de zero (https://codepre.com/pt/como-medir-la-estabilidad-de-su-conexion-a-internet-desde-su-pc.html)

## default time delay for sqli blind time-based 
DEFAULT_SQLI_TIME_BASED_TIME = 5
## counter for succed sqli bind time-based 
SQLI_BLIND_TIME_BASED_SUCCED_COUNT = 0


HEADERS = {  # default headers
    'User-Agent': '$',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Connection': 'close',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
    }

PROXIES_ = {'http': 'http://217.219.61.6:8080', 'https': 'https://217.219.61.6:8080'}#  Fonte de servidor proxy usado configurado  https://spys.one/en/

