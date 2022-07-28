#@category _MGS
import os
from ghidra.program.model.data import DataType, Pointer, Structure

dtm = currentProgram.getDataTypeManager()

root_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), '../../'))

with open (root_dir + '/build/ghidra_scripts/data_types_redux.txt', 'w') as f:
    # @todo: enums, typedefs, etc.
    for data_type in dtm.getAllStructures():
        dt_info = data_type.getName() + ';'
        for component in data_type.getComponents():
            dt_info += component.getDataType().getName() + ',' + component.getFieldName() + ',' + str(component.getLength()) + ';'
        f.write(dt_info + '\n')
