# !/usr/bin/env python3
# Author: @alien_2021[Zanzambi]
import sys
import os
import platform

colors = True  # Output should be colored
machine = sys.platform  # Detecting the os of current system
checkplatform = platform.platform() # Get current version of OS
if machine.lower().startswith(('os', 'win', 'darwin', 'ios')):
    colors = False  # Colors shouldn't be displayed in mac & windows
if checkplatform.startswith("Windows-10") and int(platform.version().split(".")[2]) >= 10586:
    colors = True
    os.system('')   # Enables the ANSI
if not colors:
    end = red = white = green = yellow = run = bad = good = roxo  = submetendo =cian = info = orange=  que = ''
else:
    white = '\033[97m' # branca
    green = '\033[92m'  # verde
    red = '\033[31m'  # vermelho
    yellow = '\033[93m'  # amarela
    end = '\033[0m'  # sem 
    back_red = '\033[7;91m' ## fundo do texto em vermelho
    info = '\033[93m[!]\033[0m' ## undo dinfo em amarelo
    admin_side = '\033[94m'  # 
    submetendo = '\033[94m[~]\033[0m'
    confirm = '\033[94m[?]\033[0m' ## violeta
    bad = '\033[91m[-]\033[0m' ## fundo do info em red
    falta = '\033[91m[!]\033[0m' # colhetes em vermelho com exclamaçao
    good = '\033[92m[+]\033[0m' ## fundo verde
    run = '\033[97m[~]\033[0m' ##core padrao
    
    
    info_1 = '\033[33m['
    red_0 = '\033[91m!'
    info_2 = '\033[33m]'
    
    roxo = '\033[35m'  # purple
    cian = '\033[36m' #cian
    orange = '\033[33m' # orange
    
    
