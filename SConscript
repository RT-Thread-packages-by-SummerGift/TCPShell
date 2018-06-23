from building import *

cwd     = GetCurrentDir()
src     = Glob('*.c')
CPPPATH = [cwd]
group   = DefineGroup('tcpshell', src, depend = ['RT_USING_tcpshell'], CPPPATH = CPPPATH)

Return('group')
