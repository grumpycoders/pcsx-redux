import os
from ghidra.program.model.data import DataType, Pointer, Structure

fm = currentProgram.getFunctionManager()
dtm = currentProgram.getDataTypeManager()

root_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), '.'))

with open (root_dir + '/redux_data_types.txt', 'w') as f:
    # @todo: enums, typedefs, etc.
    for data_type in dtm.getAllStructures():
        dt_info = data_type.getName() + ';'
        print('struct: ' + dt_info)
        for component in data_type.getComponents():
            type_name = component.getDataType().getName()
            print('type: ' + type_name)
            field_name = component.getFieldName()
            print('field name: ' + field_name)
            field_length = str(component.getLength())
            print('field length: ' + field_length)
            dt_info += type_name + ',' + field_name + ',' + field_length + ';'
        f.write(dt_info + '\n')

with open (root_dir + '/redux_funcs.txt', 'w') as f:
    main_address = 0x800148B8
    for func in fm.getFunctions(toAddr(main_address), True):
        entry_point = func.getEntryPoint().toString()
        func_info = entry_point.split(':')[-1] + ';' + func.getName() + ';'
        for param in func.getParameters():
            data_type_name = param.getDataType().getName()
            if data_type_name.__contains__('undefined'):
                data_type_name = 'int'
            func_info += data_type_name + ',' + param.getName() + ',' + str(param.getLength()) + ';'
        f.write(func_info + '\n')
