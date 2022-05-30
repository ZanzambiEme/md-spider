# /usr/bin pyhton3
'''
executa a varredura de com todas as dependências do plugin principal de SQLi
'''

from core.utils import exitTheProgram

def alien(_shell, _dump_tables, _dump_all, target_url):
    if not _shell and not _dump_tables and not _dump_all:
        ####################################################
        from mode.plugin.tablesEnum import simpleTest      #
        simpleTest(target_url)                             #
        ####################################################
    else:
        pass
    if _shell:
        from mode.plugin.tablesEnum import sqlShell
        sqlShell(target_url)                
    if _dump_tables:                
        from mode.plugin.tablesEnum import dump_tables
        dump_tables(target_url)                       
    if _dump_all:
        from mode.plugin.tablesEnum import dumpAll
        dumpAll(target_url)    # enumera todas as tables do banco de dados
        exitTheProgram()
    