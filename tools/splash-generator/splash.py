#!/usr/bin/env python3
# Generates the splash screen data the emulator displays while nothing is loaded
import sys
from PIL import Image

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <image_file>")
    sys.exit(1)

filename = sys.argv[1]

img = Image.open(filename).convert("RGBA")
width, height = img.size
pixels = list(img.getdata())

# Convert pixel data to RGBA8888
data = []
for r, g, b, a in pixels:
    val = (a << 24) | (b << 16) | (g << 8) | r
    data.append(val)

print("// Generated using tools/splash-generator/splash.py")

# First 2 u32s are the splash screen's width and height
# The rest of the array is the pixel data in little endian RGBA8888
print("static const uint32_t s_splashImageData[] = {{")
print(f"    {width}, {height},", end=" ")

for i, val in enumerate(data):
    sep = "," if i != len(data) - 1 else ""
    if i % 8 == 0:
        print("\n    ", end="")
    print(f"0x{val:08X}{sep}", end=" ")
print("\n};")
