#@category _MGS
import os
from ghidra.program.model.data import DataType, Pointer, Structure

dtm = currentProgram.getDataTypeManager()

root_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), '../../'))

with open (root_dir + '/build/ghidra_scripts/data_types_redux.txt', 'w') as f:
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
