// Copyright (c) 2013 Austin T. Clements. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

#include "internal.hh"

using namespace std;

DWARFPP_BEGIN_NAMESPACE

//////////////////////////////////////////////////////////////////
// class dwarf
//

struct dwarf::impl {
    impl(const std::shared_ptr<loader> &l) : l(l), have_type_units(false) {}

    std::shared_ptr<loader> l;

    std::shared_ptr<section> sec_info;
    std::shared_ptr<section> sec_abbrev;
    std::shared_ptr<section> sec_frame;

    std::vector<compilation_unit> compilation_units;
    std::unordered_map<section_offset, cie> cies;
    std::vector<fde> fdes;

    std::unordered_map<uint64_t, type_unit> type_units;
    bool have_type_units;

    std::map<section_type, std::shared_ptr<section> > sections;
};

dwarf::dwarf(const std::shared_ptr<loader> &l) : m(make_shared<impl>(l)) {
    const void *data;
    size_t size;

    // Get required sections
    data = l->load(section_type::info, &size);
    if (!data) throw format_error("required .debug_info section missing");
    m->sec_info = make_shared<section>(section_type::info, data, size, byte_order::lsb);

    // Sniff the endianness from the version field of the first
    // CU. This is always a small but non-zero integer.
    cursor endcur(m->sec_info);
    // Skip length.
    section_length length = endcur.fixed<uword>();
    if (length == 0xffffffff) endcur.fixed<uint64_t>();
    // Get version in both little and big endian.
    uhalf version = endcur.fixed<uhalf>();
    uhalf versionbe = (version >> 8) | ((version & 0xFF) << 8);
    if (versionbe < version) {
        m->sec_info = make_shared<section>(section_type::info, data, size, byte_order::msb);
    }

    data = l->load(section_type::abbrev, &size);
    if (!data) throw format_error("required .debug_abbrev section missing");
    m->sec_abbrev = make_shared<section>(section_type::abbrev, data, size, m->sec_info->ord);

    data = l->load(section_type::frame, &size);
    if (!data) throw format_error("required .debug_frame section missing");
    m->sec_frame = make_shared<section>(section_type::frame, data, size, m->sec_info->ord);

    // Get compilation units.  Everything derives from these, so
    // there's no point in doing it lazily.
    cursor infocur(m->sec_info);
    while (!infocur.end()) {
        // XXX Circular reference.  Given that we now require
        // the dwarf object to stick around for DIEs, maybe we
        // might as well require that for units, too.
        m->compilation_units.emplace_back(*this, infocur.get_section_offset());
        infocur.subsection();
    }

    cursor framecur(m->sec_frame);
    while (!framecur.end()) {
        auto offset = framecur.get_section_offset();

        cursor cur(m->sec_frame, offset);
        std::shared_ptr<section> subsec = cur.subsection();
        cursor sub(subsec);
        sub.skip_initial_length();

        section_offset id = sub.offset();
        if (id == subsec->marker()) {
            m->cies.emplace(std::piecewise_construct, std::forward_as_tuple(offset),
                            std::forward_as_tuple(*this, offset));
        } else {
            m->fdes.emplace_back(*this, offset);
        }

        framecur.subsection();
    }
}

dwarf::~dwarf() {}

static std::vector<compilation_unit> empty;
const std::vector<compilation_unit> &dwarf::compilation_units() const {
    if (!m) return empty;
    return m->compilation_units;
}

const std::unordered_map<section_offset, cie> &dwarf::get_cies() const { return m->cies; }
const std::vector<fde> &dwarf::get_fdes() const { return m->fdes; }

const type_unit &dwarf::get_type_unit(uint64_t type_signature) const {
    if (!m->have_type_units) {
        cursor tucur(get_section(section_type::types));
        while (!tucur.end()) {
            // XXX Circular reference
            type_unit tu(*this, tucur.get_section_offset());
            m->type_units[tu.get_type_signature()] = tu;
            tucur.subsection();
        }
        m->have_type_units = true;
    }
    if (!m->type_units.count(type_signature)) throw out_of_range("type signature 0x" + to_hex(type_signature));
    return m->type_units[type_signature];
}

std::shared_ptr<section> dwarf::get_section(section_type type) const {
    if (type == section_type::info) return m->sec_info;
    if (type == section_type::abbrev) return m->sec_abbrev;

    auto it = m->sections.find(type);
    if (it != m->sections.end()) return it->second;

    size_t size;
    const void *data = m->l->load(type, &size);
    if (!data) throw format_error(std::string(elf::section_type_to_name(type)) + " section missing");
    m->sections[type] = std::make_shared<section>(section_type::str, data, size, m->sec_info->ord);
    return m->sections[type];
}

//////////////////////////////////////////////////////////////////
// class unit
//

/**
 * Implementation of a unit.
 */
struct unit::impl {
    const dwarf file;
    const section_offset offset;
    const std::shared_ptr<section> subsec;
    const section_offset debug_abbrev_offset;
    const section_offset root_offset;

    // Type unit-only values
    const uint64_t type_signature;
    const section_offset type_offset;

    // Lazily constructed root and type DIEs
    die root, type;

    // Lazily constructed line table
    line_table lt;

    // Map from abbrev code to abbrev.  If the map is dense, it
    // will be stored in the vector; otherwise it will be stored
    // in the map.
    bool have_abbrevs;
    std::vector<abbrev_entry> abbrevs_vec;
    std::unordered_map<abbrev_code, abbrev_entry> abbrevs_map;

    impl(const dwarf &file, section_offset offset, const std::shared_ptr<section> &subsec,
         section_offset debug_abbrev_offset, section_offset root_offset, uint64_t type_signature = 0,
         section_offset type_offset = 0)
        : file(file),
          offset(offset),
          subsec(subsec),
          debug_abbrev_offset(debug_abbrev_offset),
          root_offset(root_offset),
          type_signature(type_signature),
          type_offset(type_offset),
          have_abbrevs(false) {}

    void force_abbrevs();
};

unit::~unit() {}

const dwarf &unit::get_dwarf() const { return m->file; }

section_offset unit::get_section_offset() const { return m->offset; }

const die &unit::root() const {
    if (!m->root.valid()) {
        m->force_abbrevs();
        m->root = die(this);
        m->root.read(m->root_offset);
    }
    return m->root;
}

const std::shared_ptr<section> &unit::data() const { return m->subsec; }

const abbrev_entry &unit::get_abbrev(abbrev_code acode) const {
    if (!m->have_abbrevs) m->force_abbrevs();

    if (!m->abbrevs_vec.empty()) {
        if (acode >= m->abbrevs_vec.size()) goto unknown;
        const abbrev_entry &entry = m->abbrevs_vec[acode];
        if (entry.code == 0) goto unknown;
        return entry;
    } else {
        auto it = m->abbrevs_map.find(acode);
        if (it == m->abbrevs_map.end()) goto unknown;
        return it->second;
    }

unknown:
    throw format_error("unknown abbrev code 0x" + to_hex(acode));
}

void unit::impl::force_abbrevs() {
    // XXX Compilation units can share abbrevs.  Parse each table
    // at most once.
    if (have_abbrevs) return;

    // Section 7.5.3
    cursor c(file.get_section(section_type::abbrev), debug_abbrev_offset);
    abbrev_entry entry;
    abbrev_code highest = 0;
    while (entry.read(&c)) {
        abbrevs_map[entry.code] = entry;
        if (entry.code > highest) highest = entry.code;
    }

    // Typically, abbrev codes are assigned linearly, so it's more
    // space efficient and time efficient to store the table in a
    // vector.  Convert to a vector if it's dense enough, by some
    // rough estimate of "enough".
    if (highest * 10 < abbrevs_map.size() * 15) {
        // Move the map into the vector
        abbrevs_vec.resize(highest + 1);
        for (auto &entry : abbrevs_map) abbrevs_vec[entry.first] = move(entry.second);
        abbrevs_map.clear();
    }

    have_abbrevs = true;
}

//////////////////////////////////////////////////////////////////
// class compilation_unit
//

compilation_unit::compilation_unit(const dwarf &file, section_offset offset) {
    // Read the CU header (DWARF4 section 7.5.1.1)
    cursor cur(file.get_section(section_type::info), offset);
    std::shared_ptr<section> subsec = cur.subsection();
    cursor sub(subsec);
    sub.skip_initial_length();
    uhalf version = sub.fixed<uhalf>();
    if (version < 2 || version > 4) throw format_error("unknown compilation unit version " + std::to_string(version));
    // .debug_abbrev-relative offset of this unit's abbrevs
    section_offset debug_abbrev_offset = sub.offset();
    ubyte address_size = sub.fixed<ubyte>();
    subsec->addr_size = address_size;

    m = make_shared<impl>(file, offset, subsec, debug_abbrev_offset, sub.get_section_offset());
}

struct cie::impl {
    std::shared_ptr<section> subsec;
    const ubyte version;
    const ubyte address_size;
    const ubyte segment_size;
    const uint64_t code_alignment_factor;
    const int64_t data_alignment_factor;
    const uint64_t return_address_register;

    const cursor instructions;

    impl(std::shared_ptr<section> subsec, const ubyte version, const ubyte address_size, const ubyte segment_size,
         const uint64_t code_alignment_factor, const int64_t data_alignment_factor,
         const uint64_t return_address_register, const cursor instructions)
        : subsec(subsec),
          version(version),
          address_size(address_size),
          segment_size(segment_size),
          code_alignment_factor(code_alignment_factor),
          data_alignment_factor(data_alignment_factor),
          return_address_register(return_address_register),
          instructions(instructions) {}
};

cie::cie(const dwarf &file, section_offset offset) {
    cursor cur(file.get_section(section_type::frame), offset);
    std::shared_ptr<section> subsec = cur.subsection();
    cursor sub(subsec);
    sub.skip_initial_length();
    section_offset id = sub.offset();
    ubyte version = sub.fixed<ubyte>();
    const char *augmentation = sub.cstr();

    if (id != subsec->marker()) throw format_error("wrong id for CIE");
    switch (version) {
        case 1:
        case 3:
        case 4:
            break;
        default:
            throw format_error("unknown CIE version");
            break;
    }
    if (augmentation[0]) throw format_error("unknown augmentation: " + std::string(augmentation));
    ubyte address_size;
    ubyte segment_size;

    if (version == 4) {
        address_size = sub.fixed<ubyte>();
        segment_size = sub.fixed<ubyte>();
    } else {
        address_size = 0;
        switch (subsec->fmt) {
            case format::dwarf32:
                address_size = 4;
                break;
            case format::dwarf64:
                address_size = 8;
                break;
        }
        segment_size = 0;
    }
    uint64_t code_alignment_factor = sub.uleb128();
    int64_t data_alignment_factor = sub.sleb128();
    uint64_t return_address_register = sub.uleb128();

    m = make_shared<impl>(subsec, version, address_size, segment_size, code_alignment_factor, data_alignment_factor,
                          return_address_register, sub);
}

struct fde::impl {
    std::shared_ptr<section> subsec;

    const std::unordered_map<section_offset, cie>::const_iterator CIE;
    const taddr initial_location_segment;
    const taddr initial_location;
    const size_t address_range;

    const cursor instructions;

    impl(std::shared_ptr<section> subsec, std::unordered_map<section_offset, cie>::const_iterator CIE,
         const taddr initial_location_segment, const taddr initial_location, const size_t address_range,
         const cursor instructions)
        : subsec(subsec),
          CIE(CIE),
          initial_location_segment(initial_location_segment),
          initial_location(initial_location),
          address_range(address_range),
          instructions(instructions) {}
};

fde::fde(const dwarf &file, section_offset offset) {
    cursor cur(file.get_section(section_type::frame), offset);
    std::shared_ptr<section> subsec = cur.subsection();
    cursor sub(subsec);
    sub.skip_initial_length();

    section_offset CIE_pointer = sub.offset();

    std::unordered_map<section_offset, cie>::const_iterator CIE = file.get_cies().find(CIE_pointer);
    if (CIE == file.get_cies().end()) throw format_error("missing CIE for FDE");
    taddr initial_location_segment = 0;
    if (CIE->second.m->segment_size != 0) initial_location_segment = sub.address(CIE->second.m->segment_size);
    taddr initial_location = sub.address(CIE->second.m->address_size);
    size_t address_range = sub.address(CIE->second.m->address_size);

    m = make_shared<impl>(subsec, CIE, initial_location_segment, initial_location, address_range, sub);
}

fde::fde() {}

bool fde::contains(taddr pc) const {
    taddr begin = m->initial_location;
    taddr end = begin + m->address_range;
    return (begin <= pc) && (pc < end);
}

taddr fde::initial_location() const { return m->initial_location; }
size_t fde::length() const { return m->address_range; }
bool fde::valid() const { return m.get(); }

fde::cfa fde::evaluate_cfa(taddr pc) const {
    if (!contains(pc)) throw out_of_range("evaluate_cfa: pc is not in range");

    taddr loc = m->initial_location;
    fde::cfa ret;
    std::int64_t remembered_cfa;

    cursor_chain cur({m->CIE->second.m->instructions, m->instructions});

    while (!cur.end()) {
        if (loc > pc) break;
        ubyte rawop = cur->fixed<ubyte>();
        ubyte up = rawop >> 6;
        ubyte lo = rawop & 0x3f;
        switch (up) {
            case 0: {
                DW_CFA op = (DW_CFA)rawop;
                if ((rawop >= 0x1c) && (rawop <= 0x3f)) {
                    throw runtime_error("Unimplemented user CFA ops");
                }
                switch (op) {
                    case DW_CFA::nop:
                        break;
                    case DW_CFA::set_loc:
                        loc = cur->address(m->CIE->second.m->address_size);
                        break;
                    case DW_CFA::advance_loc1:
                        loc += m->CIE->second.m->code_alignment_factor * cur->fixed<ubyte>();
                        break;
                    case DW_CFA::advance_loc2:
                        loc += m->CIE->second.m->code_alignment_factor * cur->fixed<uhalf>();
                        break;
                    case DW_CFA::advance_loc4:
                        loc += m->CIE->second.m->code_alignment_factor * cur->fixed<uword>();
                        break;
                    case DW_CFA::offset_extended: {
                        std::uint64_t reg = cur->uleb128();
                        std::int64_t offset = cur->uleb128() * m->CIE->second.m->data_alignment_factor;
                        if (reg == m->CIE->second.m->return_address_register) {
                            ret.ra_offset = offset;
                            ret.ra_offset_valid = true;
                        } else if (reg == ret.reg) {
                            ret.saved_reg_offset = offset;
                            ret.saved_reg_offset_valid = true;
                        }
                        break;
                    }
                    case DW_CFA::restore_extended:
                        cur->uleb128();
                        break;
                    case DW_CFA::undefined:
                        cur->uleb128();
                        break;
                    case DW_CFA::same_value:
                        cur->uleb128();
                        break;
                    case DW_CFA::register_:
                        cur->uleb128();
                        cur->uleb128();
                        break;
                    case DW_CFA::remember_state:
                        remembered_cfa = ret.offset;
                        break;
                    case DW_CFA::restore_state:
                        ret.offset = remembered_cfa;
                        ret.offset_valid = true;
                        break;
                    case DW_CFA::def_cfa:
                        ret.reg = cur->uleb128();
                    case DW_CFA::def_cfa_offset:
                        ret.offset = cur->uleb128();
                        ret.offset_valid = true;
                        break;
                    case DW_CFA::def_cfa_register:
                        ret.reg = cur->uleb128();
                        break;
                    case DW_CFA::def_cfa_expression:
                        throw runtime_error("DW_CFA_def_cfa_expression not implemented");
                    case DW_CFA::expression:
                        throw runtime_error("DW_CFA_expression not implemented");
                    case DW_CFA::offset_extended_sf: {
                        std::uint64_t reg = cur->uleb128();
                        std::int64_t offset = cur->sleb128() * m->CIE->second.m->data_alignment_factor;
                        if (reg == m->CIE->second.m->return_address_register) {
                            ret.ra_offset = offset;
                            ret.ra_offset_valid = true;
                        } else if (reg == ret.reg) {
                            ret.saved_reg_offset = offset;
                            ret.saved_reg_offset_valid = true;
                        }
                        break;
                    }
                    case DW_CFA::def_cfa_sf:
                        ret.reg = cur->uleb128();
                    case DW_CFA::def_cfa_offset_sf:
                        ret.offset = cur->sleb128();
                        break;
                    case DW_CFA::val_offset:
                        cur->uleb128();
                        cur->uleb128();
                        break;
                    case DW_CFA::val_offset_sf:
                        cur->uleb128();
                        cur->sleb128();
                        break;
                    case DW_CFA::val_expression:
                        throw runtime_error("DW_CFA_val_expression not implemented");
                }
                break;
            }
            case 1:  // DW_CFA_advance_loc
                loc += lo * m->CIE->second.m->code_alignment_factor;
                break;
            case 2: {  // DW_CFA_offset
                int64_t offset = cur->uleb128() * m->CIE->second.m->data_alignment_factor;
                if (lo == m->CIE->second.m->return_address_register) {
                    ret.ra_offset = offset;
                    ret.ra_offset_valid = true;
                } else if (lo == ret.reg) {
                    ret.saved_reg_offset = offset;
                    ret.saved_reg_offset_valid = true;
                }
                break;
            }
            case 3:  // DW_CFA_restore
                break;
        }
    }
    return ret;
}

const line_table &compilation_unit::get_line_table() const {
    if (!m->lt.valid()) {
        const die &d = root();
        if (!d.has(DW_AT::stmt_list) || !d.has(DW_AT::name)) goto done;

        shared_ptr<section> sec;
        try {
            sec = m->file.get_section(section_type::line);
        } catch (format_error &e) {
            goto done;
        }

        auto comp_dir = d.has(DW_AT::comp_dir) ? at_comp_dir(d) : "";

        m->lt = line_table(sec, d[DW_AT::stmt_list].as_sec_offset(), m->subsec->addr_size, comp_dir, at_name(d));
    }
done:
    return m->lt;
}

//////////////////////////////////////////////////////////////////
// class type_unit
//

type_unit::type_unit(const dwarf &file, section_offset offset) {
    // Read the type unit header (DWARF4 section 7.5.1.2)
    cursor cur(file.get_section(section_type::types), offset);
    std::shared_ptr<section> subsec = cur.subsection();
    cursor sub(subsec);
    sub.skip_initial_length();
    uhalf version = sub.fixed<uhalf>();
    if (version != 4) throw format_error("unknown type unit version " + std::to_string(version));
    // .debug_abbrev-relative offset of this unit's abbrevs
    section_offset debug_abbrev_offset = sub.offset();
    ubyte address_size = sub.fixed<ubyte>();
    subsec->addr_size = address_size;
    uint64_t type_signature = sub.fixed<uint64_t>();
    section_offset type_offset = sub.offset();

    m = make_shared<impl>(file, offset, subsec, debug_abbrev_offset, sub.get_section_offset(), type_signature,
                          type_offset);
}

uint64_t type_unit::get_type_signature() const { return m->type_signature; }

const die &type_unit::type() const {
    if (!m->type.valid()) {
        m->force_abbrevs();
        m->type = die(this);
        m->type.read(m->type_offset);
    }
    return m->type;
}

DWARFPP_END_NAMESPACE
