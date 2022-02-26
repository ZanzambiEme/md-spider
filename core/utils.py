# !/usr/bin/env python3

from fileinput import filename
import logging

def logginStore():
    try:
        import core.colors as color
        
        logging.basicConfig(filename='./logs/WebSpider.log', format='%(levelname)s [%(asctime)s] %(name)s %(process)d %(pathname)s [%(message)s]', level=logging.DEBUG, encoding='utf-8')
        
    except ImportError as e:
        print(color.bad+' erro em importar % '.format(e))
        