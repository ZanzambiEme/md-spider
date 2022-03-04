# !/usr/bin/env python3

from fileinput import filename
import logging

def logginStore():
    try:
        import core.colors as color
        
        logging.basicConfig(filename='./logs/WebSpider.log', format='%(levelname)s [%(asctime)s] %(name)s %(process)d %(pathname)s [%(message)s]', level=logging.DEBUG, encoding='utf-8')
        
    except ImportError as e:
        print(color.bad+' erro em importar % '.format(e))
        
def urlValidator(url):
    if 'http://' in url[:7]:
        return True
    elif 'https://' in url[:8]:
        return True
    if 'www' in url[:3]:
        return True
    else:
        return False