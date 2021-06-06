#!/bin/sh

brew install imagemagick dylibbundler

APP=PCSX-Redux
PATH="$PATH:/usr/libexec"

make install DESTDIR=${APP}.app/Contents/Resources
mkdir -p ${APP}.app/Contents/MacOS
ln -s ../Resources/bin/pcsx-redux ${APP}.app/Contents/MacOS/${APP}
convert resources/pcsx-redux.ico[0] -alpha on -background none ${APP}.app/Contents/Resources/app.icns
PlistBuddy ${APP}.app/Contents/Info.plist -c "add CFBundleDisplayName string ${APP}"
PlistBuddy ${APP}.app/Contents/Info.plist -c "add CFBundleIconFile string app.icns"
PlistBuddy ${APP}.app/Contents/version.plist -c "add ProjectName string ${APP}"
dylibbundler -od -b -x ./PCSX-Redux.app/Contents/Resources/bin/pcsx-redux -d ./PCSX-Redux.app/Contents/Resources/lib/ -p @executable_path/../lib/
