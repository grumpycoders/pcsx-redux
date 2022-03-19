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

#include "core/cdriso.h"
#include "core/cdrom.h"

int PCSX::CDRiso::handlepbp(const char *isofile) {
    struct {
        unsigned int sig;
        unsigned int dontcare[8];
        unsigned int psar_offs;
    } pbp_hdr;
    struct {
        unsigned char type;
        unsigned char pad0;
        unsigned char track;
        char index0[3];
        char pad1;
        char index1[3];
    } toc_entry;
    struct {
        unsigned int offset;
        unsigned int size;
        unsigned int dontcare[6];
    } index_entry;
    char psar_sig[11];
    unsigned int t, cd_length, cdimg_base;
    unsigned int offsettab[8], psisoimg_offs;
    const char *ext = NULL;
    int i, ret;

    if (strlen(isofile) >= 4) ext = isofile + strlen(isofile) - 4;
    if (ext == NULL || (strcmp(ext, ".pbp") != 0 && strcmp(ext, ".PBP") != 0)) return -1;

    m_cdHandle->rSeek(0, SEEK_SET);

    m_numtracks = 0;

    ret = m_cdHandle->read(&pbp_hdr, sizeof(pbp_hdr));
    if (ret != sizeof(pbp_hdr)) {
        PCSX::g_system->printf("failed to read pbp\n");
        goto fail_io;
    }

    ret = m_cdHandle->rSeek(pbp_hdr.psar_offs, SEEK_SET);
    if (ret != 0) {
        PCSX::g_system->printf("failed to seek to %x\n", pbp_hdr.psar_offs);
        goto fail_io;
    }

    psisoimg_offs = pbp_hdr.psar_offs;
    m_cdHandle->read(psar_sig, sizeof(psar_sig));
    psar_sig[10] = 0;
    if (strcmp(psar_sig, "PSTITLEIMG") == 0) {
        // multidisk image?
        ret = m_cdHandle->rSeek(pbp_hdr.psar_offs + 0x200, SEEK_SET);
        if (ret != 0) {
            PCSX::g_system->printf("failed to seek to %x\n", pbp_hdr.psar_offs + 0x200);
            goto fail_io;
        }

        if (m_cdHandle->read(&offsettab, sizeof(offsettab)) != sizeof(offsettab)) {
            PCSX::g_system->printf("failed to read offsettab\n");
            goto fail_io;
        }

        for (i = 0; i < sizeof(offsettab) / sizeof(offsettab[0]); i++) {
            if (offsettab[i] == 0) break;
        }
        m_cdrIsoMultidiskCount = i;
        if (m_cdrIsoMultidiskCount == 0) {
            PCSX::g_system->printf("multidisk eboot has 0 images?\n");
            goto fail_io;
        }

        if (m_cdrIsoMultidiskSelect >= m_cdrIsoMultidiskCount) m_cdrIsoMultidiskSelect = 0;

        psisoimg_offs += offsettab[m_cdrIsoMultidiskSelect];

        ret = m_cdHandle->rSeek(psisoimg_offs, SEEK_SET);
        if (ret != 0) {
            PCSX::g_system->printf("failed to seek to %x\n", psisoimg_offs);
            goto fail_io;
        }

        m_cdHandle->read(psar_sig, sizeof(psar_sig));
        psar_sig[10] = 0;
    }

    if (strcmp(psar_sig, "PSISOIMG00") != 0) {
        PCSX::g_system->printf("bad psar_sig: %s\n", psar_sig);
        goto fail_io;
    }

    // seek to TOC
    ret = m_cdHandle->rSeek(psisoimg_offs + 0x800, SEEK_SET);
    if (ret != 0) {
        PCSX::g_system->printf("failed to seek to %x\n", psisoimg_offs + 0x800);
        goto fail_io;
    }

    // first 3 entries are special
    m_cdHandle->rSeek(sizeof(toc_entry), SEEK_CUR);
    m_cdHandle->read(&toc_entry, sizeof(toc_entry));
    m_numtracks = IEC60908b::btoi(toc_entry.index1[0]);

    m_cdHandle->read(&toc_entry, sizeof(toc_entry));
    cd_length = IEC60908b::btoi(toc_entry.index1[0]) * 60 * 75 + IEC60908b::btoi(toc_entry.index1[1]) * 75 +
                IEC60908b::btoi(toc_entry.index1[2]);

    for (i = 1; i <= m_numtracks; i++) {
        m_cdHandle->read(&toc_entry, sizeof(toc_entry));

        m_ti[i].type = (toc_entry.type == 1) ? TrackType::CDDA : TrackType::DATA;

        m_ti[i].start_offset = IEC60908b::btoi(toc_entry.index0[0]) * 60 * 75 +
                               IEC60908b::btoi(toc_entry.index0[1]) * 75 + IEC60908b::btoi(toc_entry.index0[2]);
        m_ti[i].start_offset *= 2352;
        m_ti[i].start.m = IEC60908b::btoi(toc_entry.index1[0]);
        m_ti[i].start.s = IEC60908b::btoi(toc_entry.index1[1]);
        m_ti[i].start.f = IEC60908b::btoi(toc_entry.index1[2]);

        if (i > 1) {
            t = m_ti[i].start.toLBA() - m_ti[i - 1].start.toLBA();
            m_ti[i - 1].length = IEC60908b::MSF(t);
        }
    }
    t = cd_length - m_ti[m_numtracks].start_offset / 2352;
    m_ti[m_numtracks].length = IEC60908b::MSF(t);

    // seek to ISO index
    ret = m_cdHandle->rSeek(psisoimg_offs + 0x4000, SEEK_SET);
    if (ret != 0) {
        PCSX::g_system->printf("failed to seek to ISO index\n");
        goto fail_io;
    }

    m_compr_img = (compr_img_t *)calloc(1, sizeof(*m_compr_img));
    if (m_compr_img == NULL) goto fail_io;

    m_compr_img->block_shift = 4;
    m_compr_img->current_block = (unsigned int)-1;

    m_compr_img->index_len = (0x100000 - 0x4000) / sizeof(index_entry);
    m_compr_img->index_table =
        (unsigned int *)malloc((m_compr_img->index_len + 1) * sizeof(m_compr_img->index_table[0]));
    if (m_compr_img->index_table == NULL) goto fail_io;

    cdimg_base = psisoimg_offs + 0x100000;
    for (i = 0; i < m_compr_img->index_len; i++) {
        ret = m_cdHandle->read(&index_entry, sizeof(index_entry));
        if (ret != sizeof(index_entry)) {
            PCSX::g_system->printf("failed to read index_entry #%d\n", i);
            goto fail_index;
        }

        if (index_entry.size == 0) break;

        m_compr_img->index_table[i] = cdimg_base + index_entry.offset;
    }
    m_compr_img->index_table[i] = cdimg_base + index_entry.offset + index_entry.size;

    return 0;

fail_index:
    free(m_compr_img->index_table);
    m_compr_img->index_table = NULL;
fail_io:
    if (m_compr_img != NULL) {
        free(m_compr_img);
        m_compr_img = NULL;
    }
    return -1;
}
