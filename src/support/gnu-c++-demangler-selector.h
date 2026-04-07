/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

// Parse tree node selector for the GNU C++ demangler.
// Determines which grammar rules create nodes in the PEGTL parse tree.
// Rules not listed here are transparent - their children propagate to the parent.

#pragma once

#include <type_traits>

#include "support/gnu-c++-demangler-grammar.h"

namespace PCSX::GNUDemangler {

template <typename Rule>
struct DemanglerSelector : std::false_type {};

#define DEMANGLE_SELECT(rule) \
    template <>               \
    struct DemanglerSelector<rule> : std::true_type {}

// Structural nodes (seq rules that group children)
DEMANGLE_SELECT(function);
DEMANGLE_SELECT(nested_name);
DEMANGLE_SELECT(template_decl);
DEMANGLE_SELECT(template_args);
DEMANGLE_SELECT(bare_function_type);
DEMANGLE_SELECT(CV_qualified_type);
DEMANGLE_SELECT(pointer_to_type);
DEMANGLE_SELECT(reference_to_type);
DEMANGLE_SELECT(rvalue_reference_to_type);
DEMANGLE_SELECT(function_type);
DEMANGLE_SELECT(array_type_numerical);
DEMANGLE_SELECT(array_type_expression);
DEMANGLE_SELECT(pointer_to_member_type);
DEMANGLE_SELECT(substitution_simple);
DEMANGLE_SELECT(template_param);
DEMANGLE_SELECT(template_type);
DEMANGLE_SELECT(template_prefix_with_args);
DEMANGLE_SELECT(std_unqualified_name);
DEMANGLE_SELECT(std_name);
DEMANGLE_SELECT(local_name_simple);
DEMANGLE_SELECT(closure_type_name);
DEMANGLE_SELECT(data_member_prefix);
DEMANGLE_SELECT(virtual_table);
DEMANGLE_SELECT(vtt_structure);
DEMANGLE_SELECT(typeinfo_structure);
DEMANGLE_SELECT(typeinfo_name);
DEMANGLE_SELECT(guard_variable);
DEMANGLE_SELECT(expr_primary_integer);
DEMANGLE_SELECT(template_arg_expression);
DEMANGLE_SELECT(binary_operator_expression);
DEMANGLE_SELECT(unary_operator_expression);
DEMANGLE_SELECT(trinary_operator_expression);
DEMANGLE_SELECT(new_operator);
DEMANGLE_SELECT(new_array_operator);
DEMANGLE_SELECT(delete_operator);
DEMANGLE_SELECT(delete_array_operator);
DEMANGLE_SELECT(cast_operator);
DEMANGLE_SELECT(complex_pair_type);
DEMANGLE_SELECT(imaginary_type);
DEMANGLE_SELECT(vendor_extended_type);
DEMANGLE_SELECT(pack_expansion_of_type);
DEMANGLE_SELECT(template_arg_pack);

// Leaf nodes (store matched content)
DEMANGLE_SELECT(source_name);
DEMANGLE_SELECT(ctor_dtor_name);
DEMANGLE_SELECT(CV_qualifiers);
DEMANGLE_SELECT(positive_number);
DEMANGLE_SELECT(number);
DEMANGLE_SELECT(seq_id);

// Builtin types
DEMANGLE_SELECT(void_type);
DEMANGLE_SELECT(wchar_t_type);
DEMANGLE_SELECT(bool_type);
DEMANGLE_SELECT(char_type);
DEMANGLE_SELECT(signed_char_type);
DEMANGLE_SELECT(unsigned_char_type);
DEMANGLE_SELECT(short_type);
DEMANGLE_SELECT(unsigned_short_type);
DEMANGLE_SELECT(int_type);
DEMANGLE_SELECT(unsigned_int_type);
DEMANGLE_SELECT(long_type);
DEMANGLE_SELECT(unsigned_long_type);
DEMANGLE_SELECT(long_long_type);
DEMANGLE_SELECT(unsigned_long_long);
DEMANGLE_SELECT(int128_type);
DEMANGLE_SELECT(unsigned_int128_type);
DEMANGLE_SELECT(float_type);
DEMANGLE_SELECT(double_type);
DEMANGLE_SELECT(long_double_type);
DEMANGLE_SELECT(float128_type);
DEMANGLE_SELECT(ellipsis);
DEMANGLE_SELECT(ieee754_64_type);
DEMANGLE_SELECT(ieee754_128_type);
DEMANGLE_SELECT(ieee754_32_type);
DEMANGLE_SELECT(ieee754_16_type);
DEMANGLE_SELECT(char32_type);
DEMANGLE_SELECT(char16_type);
DEMANGLE_SELECT(vendor_extended_builtin_type);

// Simple operator leaves
DEMANGLE_SELECT(unary_plus_operator);
DEMANGLE_SELECT(unary_minus_operator);
DEMANGLE_SELECT(unary_address_operator);
DEMANGLE_SELECT(unary_deference_operator);
DEMANGLE_SELECT(bitwise_not_operator);
DEMANGLE_SELECT(plus_operator);
DEMANGLE_SELECT(minus_operator);
DEMANGLE_SELECT(multiply_operator);
DEMANGLE_SELECT(divide_operator);
DEMANGLE_SELECT(remainder_operator);
DEMANGLE_SELECT(bitwise_and_operator);
DEMANGLE_SELECT(bitwise_or_operator);
DEMANGLE_SELECT(bitwise_xor_operator);
DEMANGLE_SELECT(assign_operator);
DEMANGLE_SELECT(plus_assign_operator);
DEMANGLE_SELECT(minus_assign_operator);
DEMANGLE_SELECT(multiply_assign_operator);
DEMANGLE_SELECT(divide_assign_operator);
DEMANGLE_SELECT(remainder_assign_operator);
DEMANGLE_SELECT(bitwise_and_assign_operator);
DEMANGLE_SELECT(bitwise_or_assign_operator);
DEMANGLE_SELECT(bitwise_xor_assign_operator);
DEMANGLE_SELECT(left_shift_operator);
DEMANGLE_SELECT(right_shift_operator);
DEMANGLE_SELECT(left_shift_assign_operator);
DEMANGLE_SELECT(right_shift_assign_operator);
DEMANGLE_SELECT(equal_operator);
DEMANGLE_SELECT(not_equal_operator);
DEMANGLE_SELECT(less_operator);
DEMANGLE_SELECT(greater_operator);
DEMANGLE_SELECT(less_equal_operator);
DEMANGLE_SELECT(greater_equal_operator);
DEMANGLE_SELECT(logical_not_operator);
DEMANGLE_SELECT(logical_and_operator);
DEMANGLE_SELECT(logical_or_operator);
DEMANGLE_SELECT(increment_operator);
DEMANGLE_SELECT(decrement_operator);
DEMANGLE_SELECT(comma_operator);
DEMANGLE_SELECT(arrow_star_operator);
DEMANGLE_SELECT(arrow_operator);
DEMANGLE_SELECT(call_operator);
DEMANGLE_SELECT(index_operator);
DEMANGLE_SELECT(question_operator);
DEMANGLE_SELECT(sizeof_type_operator);
DEMANGLE_SELECT(sizeof_expr_operator);
DEMANGLE_SELECT(alignof_type_operator);
DEMANGLE_SELECT(alignof_expr_operator);

// Named substitutions
DEMANGLE_SELECT(substitution_std);
DEMANGLE_SELECT(substitution_std_allocator);
DEMANGLE_SELECT(substitution_std_basic_string);
DEMANGLE_SELECT(substitution_std_basic_string_full);
DEMANGLE_SELECT(substitution_std_basic_istream);
DEMANGLE_SELECT(substitution_std_basic_ostream);
DEMANGLE_SELECT(substitution_std_basic_iostream);

#undef DEMANGLE_SELECT

}  // namespace PCSX::GNUDemangler
