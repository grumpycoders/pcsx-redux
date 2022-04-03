/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "cdrom/cdriso.h"

bool PCSX::CDRIso::handlecbin(const char *isofile) {
    struct {
        char magic[4];
        unsigned int header_size;
        unsigned long long total_bytes;
        unsigned int block_size;
        unsigned char ver;  // 1
        unsigned char align;
        unsigned char rsv_06[2];
    } ciso_hdr;
    const char *ext = NULL;
    unsigned int index = 0, plain;
    int i, ret;
    size_t read_len = 0;

    if (strlen(isofile) >= 5) ext = isofile + strlen(isofile) - 5;
    if (ext == NULL || (!StringsHelpers::strcasecmp(ext + 1, ".cbn") && !StringsHelpers::strcasecmp(ext, ".cbin") != 0))
        return false;

    m_cdHandle->rSeek(0, SEEK_SET);

    ret = m_cdHandle->read(&ciso_hdr, sizeof(ciso_hdr));
    if (ret != sizeof(ciso_hdr)) {
        PCSX::g_system->printf("failed to read ciso header\n");
        return false;
    }

    if (strncmp(ciso_hdr.magic, "CISO", 4) != 0 || ciso_hdr.total_bytes <= 0 || ciso_hdr.block_size <= 0) {
        PCSX::g_system->printf("bad ciso header\n");
        return false;
    }
    if (ciso_hdr.header_size != 0 && ciso_hdr.header_size != sizeof(ciso_hdr)) {
        ret = m_cdHandle->rSeek(ciso_hdr.header_size, SEEK_SET);
        if (ret != 0) {
            PCSX::g_system->printf("failed to seek to %x\n", ciso_hdr.header_size);
            return false;
        }
    }

    m_compr_img = (compr_img_t *)calloc(1, sizeof(*m_compr_img));
    if (m_compr_img == NULL) goto fail_io;

    m_compr_img->block_shift = 0;
    m_compr_img->current_block = (unsigned int)-1;

    m_compr_img->index_len = ciso_hdr.total_bytes / ciso_hdr.block_size;
    m_compr_img->index_table =
        (unsigned int *)malloc((m_compr_img->index_len + 1) * sizeof(m_compr_img->index_table[0]));
    if (m_compr_img->index_table == NULL) goto fail_io;

    read_len = sizeof(m_compr_img->index_table[0]) * m_compr_img->index_len;
    ret = m_cdHandle->read(m_compr_img->index_table, read_len);
    if (ret != read_len) {
        PCSX::g_system->printf("failed to read index table\n");
        goto fail_index;
    }

    for (i = 0; i < m_compr_img->index_len + 1; i++) {
        index = m_compr_img->index_table[i];
        plain = index & 0x80000000;
        index &= 0x7fffffff;
        m_compr_img->index_table[i] = (index << ciso_hdr.align) | plain;
    }
    if ((int64_t)index << ciso_hdr.align >= 0x80000000ll) {
        PCSX::g_system->printf("warning: ciso img too large, expect problems\n");
    }

    return true;

fail_index:
    free(m_compr_img->index_table);
    m_compr_img->index_table = NULL;
fail_io:
    if (m_compr_img != NULL) {
        free(m_compr_img);
        m_compr_img = NULL;
    }
    return false;
}
