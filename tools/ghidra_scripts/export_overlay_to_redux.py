"""
# Improved version of "export_to_redux.py" script by Nicolas
# that supports overlays filtering with GUI component
# Usage:
#    1. Run the script.
#    2. Paste the main function address.
#    3. Select PCSX-Redux Folder.
#    4. Select the overlays you need, the only selected overlays symbols will be exported.
"""
#@author Nicolas "Pixel" Noble
#@author acemon33

import os
from ghidra.program.model.data import DataType, Pointer, Structure


selected_overlays = []
memory_block_list = []
filter_list = []


def find_overlays():
    for mem in currentProgram.getMemory().getBlocks():
        if mem.isOverlay():
            memory_block_list.append(mem.getName())


def filter_memory_block():
    for memory_block_name in selected_overlays:
        filter_list.append(memory_block_name + '::')


def print_overlays():
    for i in range(0, len(memory_block_list)):
        print(i + 1, memory_block_list[i])


main_address = int(str(askAddress("Enter the main Address", "Address")), 16)
root_dir = askDirectory("Select PCSX-Redux Directory", "Select")
fm = currentProgram.getFunctionManager()
dtm = currentProgram.getDataTypeManager()

find_overlays()
selected_overlays = askChoices("Title", "Message", memory_block_list);

filter_memory_block()
print('main: ', hex(main_address))
print('Selected Modules : ', selected_overlays)

filename = os.path.join(str(root_dir), 'redux_data_types.txt')
with open(filename, 'w') as f:
    # @todo: enums, typedefs, etc.
    for data_type in dtm.getAllStructures():
        dt_info = data_type.getName() + ';'
        for component in data_type.getComponents():
            type_name = component.getDataType().getName()
            field_name = component.getFieldName()
            if field_name == None:
                field_name = 'None'
            field_length = str(component.getLength())
            dt_info += type_name + ',' + field_name + ',' + field_length + ';'
        f.write(dt_info + '\n')

filename = os.path.join(str(root_dir), 'redux_funcs.txt')
with open(filename, 'w') as f:
    for func in fm.getFunctions(toAddr(main_address), True):
        entry_point = func.getEntryPoint().toString()
        in_overlay = entry_point.find('::')
        if (in_overlay == -1) or (entry_point[:in_overlay+2] in filter_list): 
            num_addr = int(entry_point.split(':')[-1], 16)
            func_info = entry_point.split(':')[-1] + ';' + func.getName() + ';'
            for param in func.getParameters():
                data_type_name = param.getDataType().getName()
                if data_type_name.__contains__('undefined'):
                    data_type_name = 'int'
                func_info += data_type_name + ',' + param.getName() + ',' + str(param.getLength()) + ';'
            f.write(func_info + '\n')

popup('Finish')
