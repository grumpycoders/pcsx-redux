/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include "psyqo/cdrom-pcdrv.hh"

void psyqo::CDRomPCDrv::readSectors(uint32_t sector, uint32_t count, void *buffer,
									eastl::function<void(bool)> &&callback) {
	auto b = ensureOpen();
	if (m_isoHandle < 0) {
		callback(false);
		return;
	}

	uint8_t *dst = reinterpret_cast<uint8_t *>(buffer);
	for (uint32_t i = 0; i < count; i++) {
		uint32_t offset = (i + sector) * 2352 + 24;
		int pos = PClseek(m_isoHandle, offset, 0 /* SEEK_SET */);
		if (pos < 0) {
			callback(false);
			return;
		}

		int bytesRead = PCread(m_isoHandle, dst + i * 2048, 2048);
		if (bytesRead != 2048) {
			callback(false);
			return;
		}
	}

	callback(true);
}
