# PCSX-Redux' Ghidra scripts

This directory contains scripts that can be loaded within Ghidra to interact with PCSX-Redux somewhat. In order to configure Ghidra, while in an opened code browser, go to `Window -> Bundle Manager`, then click the green `+` button on the top right, and select this directory from your filesystem.

In order to run the scripts, go to `Window -> Script Manager`, then locate the script you want to run using the filters. Right click the script in the list, and select `Run Script`. You may want to assign a key binding in the same contextual menu to simplify user experience.

## ReduxSymbols
This script will connect to PCSX-Redux from Ghidra using the webserver, and upload the current list of symbols from the opened code browser. The list will be merged with the existing list of symbols in Redux. The web server in PCSX-Redux needs to be enabled. The script hardcodes the IP and port of PCSX-Redux, and you may want to change the script to account for different URL settings.
