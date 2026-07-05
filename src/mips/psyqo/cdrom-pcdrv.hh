#include "cdrom.hh"
#include "common/kernel/pcdrv.h"
#include "xprintf.h"


namespace psyqo {
class CDRomPCDrv final : public CDRom {
public:
    // instead of eagerly opening in the constructor:
    CDRomPCDrv(const char* isoName) : m_isoName(isoName) {}

    bool ensureOpen() {
        if (m_isoHandle < 0) {
            m_isoHandle = PCopen(m_isoName, 0, 0);
        }
        return m_isoHandle >= 0;
    }

    void readSectors(uint32_t sector, uint32_t count, void *buffer, eastl::function<void(bool)> &&callback) override;
private:
    int m_isoHandle = -1;
    const char* m_isoName;
};
}
