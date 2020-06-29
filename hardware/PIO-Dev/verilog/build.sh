#!/bin/bash
set -xe

. /opt/Xilinx/14.7/ISE_DS/settings64.sh
mkdir -p xst/projnav.tmp
xst -intstyle ise -ifn piodev3.xst -ofn piodev3.syr
ngdbuild -intstyle ise -dd _ngo -uc piodev3.ucf -p xc95144xl-TQ100-10 piodev3.ngc piodev3.ngd
cpldfit -intstyle ise -p xc95144xl-10-TQ100 -ofmt vhdl -optimize speed -htmlrpt -loc on -slew fast -init low -inputs 54 -pterms 25 -unused float -power std -terminate keeper piodev3.ngd
XSLTProcess piodev3_build.xml
tsim -intstyle ise piodev3 piodev3.nga
hprep6 -s IEEE1149 -n piodev3 -i piodev3
