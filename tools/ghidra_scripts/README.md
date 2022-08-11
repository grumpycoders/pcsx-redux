# PCSX-Redux' Ghidra scripts

This directory contains scripts that can be loaded within Ghidra to interact with PCSX-Redux somewhat. In order to configure Ghidra, while in an opened code browser, go to `Window -> Bundle Manager`, then click the green `+` button on the top right, and select this directory from your filesystem.

In order to run the scripts, go to `Window -> Script Manager`, then locate the script you want to run using the filters. Right click the script in the list, and select `Run Script`. You may want to assign a key binding in the same contextual menu to simplify user experience.

## ReduxSymbols
This script will connect to PCSX-Redux from Ghidra using the webserver, and upload the current list of symbols from the opened code browser. The list will be merged with the existing list of symbols in Redux. The web server in PCSX-Redux needs to be enabled. The script hardcodes the IP and port of PCSX-Redux, and you may want to change the script to account for different URL settings.

## export_to_redux.py
This script will generate two files consumed by the Typed Debugger (accessed from the Debug submenu):

 - redux_data_types.txt: this contains a description of all the structs in Ghidra's Data Type Manager.
 - redux_funcs.txt: this contains a description of all the functions in Ghidra's Function Manager.

This allows mapping structs defined in Ghidra to runtime memory in PCSX-Redux, with the possibility of viewing field values in accordance with their described types, editing them, setting read and write breakpoints for the fields, logging read and write instructions accessing them, and toggling those instructions; it also allows setting breakpoints for described functions where arguments have their values given in accordance with their described types, as well as toggling entire functions.
