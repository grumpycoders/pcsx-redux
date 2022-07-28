#@category _MGS
import os

fm = currentProgram.getFunctionManager()
dtm = currentProgram.getDataTypeManager()

root_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), '../../'))

with open (root_dir + '/build/ghidra_scripts/funcs_redux.txt', 'w') as f:
    for func in fm.getFunctions(toAddr(0x800148B8), True):
        func_info = func.getEntryPoint().toString() + ';' + func.getName() + ';'
        for param in func.getParameters():
            data_type_name = param.getDataType().getName()
            if data_type_name.__contains__('undefined'):
                data_type_name = 'int'
            func_info += data_type_name + ',' + param.getName() + ',' + str(param.getLength()) + ';'
        f.write(func_info + '\n')
