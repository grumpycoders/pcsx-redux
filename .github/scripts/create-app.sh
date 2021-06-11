#!/bin/sh

brew install imagemagick dylibbundler

APP=PCSX-Redux
PATH="$PATH:/usr/libexec"

mkdir pcsx-redux.iconset
convert resources/pcsx-redux.ico[0] -alpha on -background none -units PixelsPerInch -density 72 -resize 16x16 pcsx-redux.iconset/icon_16x16.png
convert resources/pcsx-redux.ico[0] -alpha on -background none -units PixelsPerInch -density 144 -resize 32x32 pcsx-redux.iconset/icon_16x16@2x.png
convert resources/pcsx-redux.ico[0] -alpha on -background none -units PixelsPerInch -density 72 -resize 32x32 pcsx-redux.iconset/icon_32x32.png
convert resources/pcsx-redux.ico[0] -alpha on -background none -units PixelsPerInch -density 144 -resize 64x64 pcsx-redux.iconset/icon_32x32@2x.png
convert resources/pcsx-redux.ico[0] -alpha on -background none -units PixelsPerInch -density 72 -resize 128x128 pcsx-redux.iconset/icon_128x128.png
convert resources/pcsx-redux.ico[0] -alpha on -background none -units PixelsPerInch -density 144 -resize 256x256 pcsx-redux.iconset/icon_128x128@2x.png
convert resources/pcsx-redux.ico[0] -alpha on -background none -units PixelsPerInch -density 72 -resize 256x256 pcsx-redux.iconset/icon_256x256.png
convert resources/pcsx-redux.ico[0] -alpha on -background none -units PixelsPerInch -density 144 -resize 512x512 pcsx-redux.iconset/icon_256x256@2x.png
convert resources/pcsx-redux.ico[0] -alpha on -background none -units PixelsPerInch -density 72 -resize 512x512 pcsx-redux.iconset/icon_512x512.png
convert resources/pcsx-redux.ico[0] -alpha on -background none -units PixelsPerInch -density 144 -resize 1024x1024 pcsx-redux.iconset/icon_512x512@2x.png
iconutil --convert icns pcsx-redux.iconset

make install DESTDIR=${APP}.app/Contents/Resources
mkdir -p ${APP}.app/Contents/MacOS
ln -s ../Resources/bin/pcsx-redux ${APP}.app/Contents/MacOS/${APP}
PlistBuddy ${APP}.app/Contents/Info.plist -c "add CFBundleDisplayName string ${APP}"
PlistBuddy ${APP}.app/Contents/Info.plist -c "add CFBundleIconFile string pcsx-redux.icns"
PlistBuddy ${APP}.app/Contents/version.plist -c "add ProjectName string ${APP}"
dylibbundler -od -b -x ./PCSX-Redux.app/Contents/Resources/bin/pcsx-redux -d ./PCSX-Redux.app/Contents/Resources/lib/ -p @executable_path/../lib/
cp pcsx-redux.icns ${APP}.app/Contents/Resources/
