#!/bin/sh

APP=PCSX-Redux
APPROOT="${APP}.app"

# /usr/libexec needed for PlistBuddy used below.
PATH="$PATH:/usr/libexec"

# ImageMagik used for converting .ico files to .png files.
# dylibbundler used for updating load commands for dylib dependencies.
brew install imagemagick dylibbundler

# Construct the app iconset.
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

# Install the contents into ./Contents/Resources temporarily.
make install DESTDIR=${APPROOT}/Contents/Resources

# Move the executable to ./Contents/MacOS/PCSX-Redux.
mkdir -p ${APPROOT}/Contents/MacOS
mv ${APPROOT}/Contents/Resources/bin/pcsx-redux ${APPROOT}/Contents/MacOS/${APP}

# Delete the now empty bin directory.
rmdir ${APPROOT}/Contents/Resources/bin

# Copy the app icon to the expected location.
cp pcsx-redux.icns ${APPROOT}/Contents/Resources/AppIcon.icns

# Remove source images that were used to create the app icon.
rm -rfv ${APPROOT}/Contents/Resources/share/icons

# Create the required Info.plist and version.plist files
# with the minimum information.
PlistBuddy ${APPROOT}/Contents/Info.plist -c "add CFBundleDisplayName string ${APP}"
PlistBuddy ${APPROOT}/Contents/Info.plist -c "add CFBundleIconName string AppIcon"
PlistBuddy ${APPROOT}/Contents/Info.plist -c "add CFBundleIconFile string AppIcon"
PlistBuddy ${APPROOT}/Contents/Info.plist -c "add NSHighResolutionCapable bool true"
PlistBuddy ${APPROOT}/Contents/version.plist -c "add ProjectName string ${APP}"

# Install dylib dependencies in ./Contents/Frameworks.
# Update the dyld load commands for these.
dylibbundler -od -b -x ${APPROOT}/Contents/MacOS/${APP} -d ${APPROOT}/Contents/Frameworks/ -p @rpath

# Add a relative @rpath to ./Contents/Frameworks
# so that dyld knows where to find dylib dependencies.
install_name_tool -add_rpath @loader_path/../Frameworks ${APPROOT}/Contents/MacOS/${APP}

# Linux desktop shortcuts not relevant.
rm -rfv ${APPROOT}/Contents/Resources/share/applications
