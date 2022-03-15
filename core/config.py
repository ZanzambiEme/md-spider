#variaveis e Constantes


from http.client import REQUEST_TIMEOUT


ACTION_VALIDATE  = False
REQUEST_TIMEOUT  = 10
INPUTS_NUBERS = 0
TARGET_VULNERABLE = False


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

