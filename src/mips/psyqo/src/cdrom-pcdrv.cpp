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
