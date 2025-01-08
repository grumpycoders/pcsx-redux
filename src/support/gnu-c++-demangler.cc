/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
// for IsDebuggerPresent
#include <Debugapi.h>
#endif

#include <cctype>
#include <string>
#include <string_view>
#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/analyze.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>
#include <tao/pegtl/contrib/parse_tree_to_dot.hpp>
#include <tao/pegtl/contrib/trace.hpp>
#include <tao/pegtl/demangle.hpp>
#include <typeinfo>
#include <vector>

#include "support/gnu-c++-demangler.h"

namespace pegtl = TAO_PEGTL_NAMESPACE;

namespace PCSX::GNUDemangler {

#ifdef _WIN32
void debugbreak() {
    if (IsDebuggerPresent()) __debugbreak();
}
#else
void debugbreak() {}
#endif

// The global parser state
struct DemanglerState {
    std::string tostring() { return ""; }
    std::vector<std::string> bag;
    std::string_view lastName;
    const std::type_info* lastAction;
};

// Unimplemented exception to throw
struct Unimplemented {
    Unimplemented(std::string_view name) : name(name) {}
    std::string_view name;
};

// Forward declarations
struct array_type;
struct bare_function_type;
struct builtin_type;
struct closure_type_name;
struct ctor_dtor_name;
struct CV_qualifiers;
struct data_member_prefix;
struct encoding;
struct expression;
struct expr_primary;
struct function;
struct function_type;
struct local_name;
struct mangled_name;
struct name;
struct nested_name;
struct operator_name;
struct pointer_to_member_type;
struct prefix;
struct source_name;
struct special_name;
struct std_name;
struct std_unqualified_name;
struct substitution;
struct template_arg;
struct template_args;
struct template_decl;
struct template_param;
struct template_prefix;
struct template_prefix_with_args;
struct template_template_param;
struct type;
struct unnamed_type_name;
struct unqualified_name;
struct unscoped_name;
struct unscoped_template_name;

// Grammar rules, in order of appearance in the grammar
// See https://refspecs.linuxfoundation.org/cxxabi-1.86.html#mangling
struct mangled_name : pegtl::seq<pegtl::string<'_', 'Z'>, encoding, pegtl::eof> {};

struct encoding : pegtl::sor<function, name, special_name> {};
struct function : pegtl::seq<name, bare_function_type> {};
struct name : pegtl::sor<nested_name, template_decl, unscoped_name, local_name, std_name> {};
struct template_decl : pegtl::seq<unscoped_template_name, template_args> {};
struct unscoped_name : pegtl::sor<unqualified_name, std_unqualified_name> {};
struct std_unqualified_name : pegtl::seq<pegtl::string<'S', 't'>, unqualified_name> {};
struct unscoped_template_name : pegtl::sor<unscoped_name, substitution> {};
struct nested_name
    : pegtl::seq<pegtl::one<'N'>, pegtl::opt<CV_qualifiers>,
                 pegtl::star<pegtl::seq<pegtl::plus<prefix>, pegtl::opt<template_args>>>, pegtl::one<'E'>> {};
struct prefix
    : pegtl::sor<template_param, substitution, template_prefix_with_args, unqualified_name, data_member_prefix> {};
struct template_prefix_with_args : pegtl::seq<template_prefix, template_args> {};
struct template_prefix : pegtl::sor<template_param, substitution> {};
struct unqualified_name : pegtl::sor<operator_name, ctor_dtor_name, source_name, unnamed_type_name> {};

struct source_name {
    using rule_t = source_name;
    using subs_t = pegtl::nothing<void>;

    template <pegtl::apply_mode A, pegtl::rewind_mode M, template <typename...> class Action,
              template <typename...> class Control, typename ParseInput, typename... States>
    [[nodiscard]] static bool match(ParseInput& in, States&&... st) {
        auto marker = in.template mark<M>();
        unsigned size = 0;
        while (in.size() > 0 && std::isdigit(in.peek_char())) {
            size *= 10;
            size += in.peek_char() - '0';
            in.bump(1);
        }
        if (size == 0) return marker(false);
        if (in.size() < size) return marker(false);
        in.bump(size);
        return marker(true);
    }
};

struct new_operator : pegtl::seq<pegtl::string<'n', 'w'>, type> {};
struct new_array_operator : pegtl::seq<pegtl::string<'n', 'a'>, type> {};
struct delete_operator : pegtl::seq<pegtl::string<'d', 'l'>, type> {};
struct delete_array_operator : pegtl::seq<pegtl::string<'d', 'a'>, type> {};
struct unary_plus_operator : pegtl::string<'p', 's'> {};
struct unary_minus_operator : pegtl::string<'n', 'g'> {};
struct unary_address_operator : pegtl::string<'a', 'd'> {};
struct unary_deference_operator : pegtl::string<'d', 'e'> {};
struct bitwise_not_operator : pegtl::string<'c', 'o'> {};
struct plus_operator : pegtl::string<'p', 'l'> {};
struct minus_operator : pegtl::string<'m', 'i'> {};
struct multiply_operator : pegtl::string<'m', 'l'> {};
struct divide_operator : pegtl::string<'d', 'v'> {};
struct remainder_operator : pegtl::string<'r', 'm'> {};
struct bitwise_and_operator : pegtl::string<'a', 'n'> {};
struct bitwise_or_operator : pegtl::string<'o', 'r'> {};
struct bitwise_xor_operator : pegtl::string<'e', 'o'> {};
struct assign_operator : pegtl::string<'a', 'S'> {};
struct plus_assign_operator : pegtl::string<'p', 'L'> {};
struct minus_assign_operator : pegtl::string<'m', 'I'> {};
struct multiply_assign_operator : pegtl::string<'m', 'L'> {};
struct divide_assign_operator : pegtl::string<'d', 'V'> {};
struct remainder_assign_operator : pegtl::string<'r', 'M'> {};
struct bitwise_and_assign_operator : pegtl::string<'a', 'N'> {};
struct bitwise_or_assign_operator : pegtl::string<'o', 'R'> {};
struct bitwise_xor_assign_operator : pegtl::string<'e', 'O'> {};
struct left_shift_operator : pegtl::string<'l', 's'> {};
struct right_shift_operator : pegtl::string<'r', 's'> {};
struct left_shift_assign_operator : pegtl::string<'l', 'S'> {};
struct right_shift_assign_operator : pegtl::string<'r', 'S'> {};
struct equal_operator : pegtl::string<'e', 'q'> {};
struct not_equal_operator : pegtl::string<'n', 'e'> {};
struct less_operator : pegtl::string<'l', 't'> {};
struct greater_operator : pegtl::string<'g', 't'> {};
struct less_equal_operator : pegtl::string<'l', 'e'> {};
struct greater_equal_operator : pegtl::string<'g', 'e'> {};
struct logical_not_operator : pegtl::string<'n', 't'> {};
struct logical_and_operator : pegtl::string<'a', 'a'> {};
struct logical_or_operator : pegtl::string<'o', 'r'> {};
struct increment_operator : pegtl::string<'p', 'p'> {};
struct decrement_operator : pegtl::string<'m', 'm'> {};
struct comma_operator : pegtl::string<'c', 'm'> {};
struct arrow_star_operator : pegtl::string<'p', 'm'> {};
struct arrow_operator : pegtl::string<'p', 't'> {};
struct call_operator : pegtl::string<'c', 'l'> {};
struct index_operator : pegtl::string<'i', 'x'> {};
struct question_operator : pegtl::string<'q', 'u'> {};
struct sizeof_type_operator : pegtl::string<'s', 't'> {};
struct sizeof_expr_operator : pegtl::string<'s', 'z'> {};
struct alignof_type_operator : pegtl::string<'a', 't'> {};
struct alignof_expr_operator : pegtl::string<'a', 'z'> {};
struct cast_operator : pegtl::seq<pegtl::string<'c', 'v'>, type> {};
struct vendor_extended_operator : pegtl::seq<pegtl::one<'v'>, pegtl::digit, source_name> {};
struct operator_name
    : pegtl::sor<new_operator, new_array_operator, delete_operator, delete_array_operator, unary_plus_operator,
                 unary_minus_operator, unary_address_operator, unary_deference_operator, bitwise_not_operator,
                 plus_operator, minus_operator, multiply_operator, divide_operator, remainder_operator,
                 bitwise_and_operator, bitwise_or_operator, bitwise_xor_operator, assign_operator, plus_assign_operator,
                 minus_assign_operator, multiply_assign_operator, divide_assign_operator, remainder_assign_operator,
                 bitwise_and_assign_operator, bitwise_or_assign_operator, bitwise_xor_assign_operator,
                 left_shift_operator, right_shift_operator, left_shift_assign_operator, right_shift_assign_operator,
                 equal_operator, not_equal_operator, less_operator, greater_operator, less_equal_operator,
                 greater_equal_operator, logical_not_operator, logical_and_operator, logical_or_operator,
                 increment_operator, decrement_operator, comma_operator, arrow_star_operator, arrow_operator,
                 call_operator, index_operator, question_operator, sizeof_type_operator, sizeof_expr_operator,
                 alignof_type_operator, alignof_expr_operator, cast_operator, vendor_extended_operator> {};

struct positive_number : pegtl::plus<pegtl::digit> {};
struct number : pegtl::seq<pegtl::opt<pegtl::one<'n'>>, positive_number> {};

struct nv_offset : pegtl::seq<pegtl::one<'h'>, number> {};
struct v_offset : pegtl::seq<pegtl::one<'v'>, number, pegtl::one<'_'>, number> {};
struct call_offset : pegtl::sor<nv_offset, v_offset> {};

struct virtual_table : pegtl::seq<pegtl::string<'T', 'V'>, type> {};
struct vtt_structure : pegtl::seq<pegtl::string<'T', 'T'>, type> {};
struct typeinfo_structure : pegtl::seq<pegtl::string<'T', 'I'>, type> {};
struct typeinfo_name : pegtl::seq<pegtl::string<'T', 'N'>, type> {};
struct guard_variable : pegtl::seq<pegtl::string<'G', 'V'>, type> {};
struct virtual_thunk : pegtl::seq<pegtl::one<'T'>, call_offset> {};
struct virtual_covariant_thunk : pegtl::seq<pegtl::string<'T', 'c'>, call_offset, call_offset> {};
struct special_name : pegtl::sor<virtual_table, vtt_structure, typeinfo_structure, typeinfo_name, guard_variable,
                                 virtual_thunk, virtual_covariant_thunk> {};

struct ctor_dtor_name : pegtl::sor<pegtl::string<'C', '1'>, pegtl::string<'C', '2'>, pegtl::string<'C', '3'>,
                                   pegtl::string<'D', '0'>, pegtl::string<'D', '1'>, pegtl::string<'D', '2'>> {};

struct template_type : pegtl::seq<template_template_param, template_args> {};
struct CV_qualified_type : pegtl::seq<CV_qualifiers, type> {};
struct pointer_to_type : pegtl::seq<pegtl::one<'P'>, type> {};
struct reference_to_type : pegtl::seq<pegtl::one<'R'>, type> {};
struct rvalue_reference_to_type : pegtl::seq<pegtl::one<'O'>, type> {};
struct complex_pair_type : pegtl::seq<pegtl::one<'C'>, type> {};
struct imaginary_type : pegtl::seq<pegtl::one<'G'>, type> {};
struct vendor_extended_type : pegtl::seq<pegtl::one<'U'>, source_name, type> {};
struct pack_expansion_of_type : pegtl::seq<pegtl::string<'D', 'p'>, type> {};
struct decltype_of_id_expression : pegtl::seq<pegtl::string<'D', 't'>, expression, pegtl::one<'E'>> {};
struct decltype_of_expression : pegtl::seq<pegtl::string<'D', 'T'>, expression, pegtl::one<'E'>> {};
struct type : pegtl::sor<builtin_type, function_type, name, array_type, pointer_to_member_type, template_param,
                         template_type, substitution, CV_qualified_type, pointer_to_type, reference_to_type,
                         rvalue_reference_to_type, complex_pair_type, imaginary_type, vendor_extended_type,
                         pack_expansion_of_type, decltype_of_id_expression, decltype_of_expression> {};

struct CV_qualifiers : pegtl::sor<pegtl::string<'r', 'V', 'K'>, pegtl::string<'r', 'V'>, pegtl::string<'r', 'K'>,
                                  pegtl::string<'V', 'K'>, pegtl::string<'r'>, pegtl::string<'V'>, pegtl::string<'K'>> {
};

struct void_type : pegtl::string<'v'> {};
struct wchar_t_type : pegtl::string<'w'> {};
struct bool_type : pegtl::string<'b'> {};
struct char_type : pegtl::string<'c'> {};
struct signed_char_type : pegtl::string<'a'> {};
struct unsigned_char_type : pegtl::string<'h'> {};
struct short_type : pegtl::string<'s'> {};
struct unsigned_short_type : pegtl::string<'t'> {};
struct int_type : pegtl::string<'i'> {};
struct unsigned_int_type : pegtl::string<'j'> {};
struct long_type : pegtl::string<'l'> {};
struct unsigned_long_type : pegtl::string<'m'> {};
struct long_long_type : pegtl::string<'x'> {};
struct unsigned_long_long : pegtl::string<'y'> {};
struct int128_type : pegtl::string<'n'> {};
struct unsigned_int128_type : pegtl::string<'o'> {};
struct float_type : pegtl::string<'f'> {};
struct double_type : pegtl::string<'d'> {};
struct long_double_type : pegtl::string<'e'> {};
struct float128_type : pegtl::string<'g'> {};
struct ellipsis : pegtl::string<'z'> {};
struct ieee754_64_type : pegtl::string<'D', 'd'> {};
struct ieee754_128_type : pegtl::string<'D', 'e'> {};
struct ieee754_32_type : pegtl::string<'D', 'f'> {};
struct ieee754_16_type : pegtl::string<'D', 'h'> {};
struct char32_type : pegtl::string<'D', 'i'> {};
struct char16_type : pegtl::string<'D', 's'> {};
struct vendor_extended_builtin_type : pegtl::seq<pegtl::string<'u'>, source_name> {};
struct builtin_type
    : pegtl::sor<void_type, wchar_t_type, bool_type, char_type, signed_char_type, unsigned_char_type, short_type,
                 unsigned_short_type, int_type, unsigned_int_type, long_type, unsigned_long_type, long_long_type,
                 unsigned_long_long, int128_type, unsigned_int128_type, float_type, double_type, long_double_type,
                 float128_type, ellipsis, ieee754_64_type, ieee754_128_type, ieee754_32_type, ieee754_16_type,
                 char32_type, char16_type, vendor_extended_builtin_type> {};

struct function_type : pegtl::seq<pegtl::one<'F'>, pegtl::opt<pegtl::one<'Y'>>, bare_function_type, pegtl::one<'E'>> {};
struct bare_function_type : pegtl::plus<type> {};

struct array_type_numerical : pegtl::seq<pegtl::one<'A'>, positive_number, pegtl::one<'_'>, type> {};
struct array_type_expression : pegtl::seq<pegtl::one<'A'>, pegtl::opt<expression>, pegtl::one<'_'>, type> {};
struct array_type : pegtl::sor<array_type_numerical, array_type_expression> {};

struct pointer_to_member_type : pegtl::seq<pegtl::one<'M'>, type, type> {};

struct template_param : pegtl::seq<pegtl::one<'T'>, pegtl::opt<number>, pegtl::one<'_'>> {};
struct template_template_param : pegtl::sor<template_param, substitution> {};

struct function_param : pegtl::seq<pegtl::string<'f', 'p'>, pegtl::opt<number>, pegtl::one<'_'>> {};

struct template_args : pegtl::seq<pegtl::one<'I'>, pegtl::plus<template_arg>, pegtl::one<'E'>> {};
struct template_arg_expression : pegtl::seq<pegtl::one<'X'>, expression, pegtl::one<'E'>> {};
struct template_arg_pack : pegtl::seq<pegtl::one<'I'>, pegtl::star<template_arg>, pegtl::one<'E'>> {};
struct template_pack_expansion : pegtl::seq<pegtl::string<'s', 'p'>, expression> {};
struct template_arg
    : pegtl::sor<type, template_arg_expression, expr_primary, template_pack_expansion, template_arg_pack> {};

struct unary_operator_expression : pegtl::seq<operator_name, expression> {};
struct binary_operator_expression : pegtl::seq<operator_name, expression, expression> {};
struct trinary_operator_expression : pegtl::seq<operator_name, expression, expression, expression> {};
struct call_expression : pegtl::seq<pegtl::string<'c', 'l'>, pegtl::plus<expression>, pegtl::one<'E'>> {};
struct conversion_expression : pegtl::seq<pegtl::string<'c', 'v'>, type, expression> {};
struct conversion_multiple_expression
    : pegtl::seq<pegtl::string<'c', 'v'>, type, pegtl::one<'_'>, pegtl::star<expression>, pegtl::one<'E'>> {};
struct sizeof_expression : pegtl::seq<pegtl::string<'s', 't'>, type> {};
struct alignof_expression : pegtl::seq<pegtl::string<'a', 't'>, type> {};
struct dependent_name_expression : pegtl::seq<pegtl::string<'s', 'r'>, type, unqualified_name> {};
struct dependent_template_id_expression : pegtl::seq<pegtl::string<'s', 't'>, type, unqualified_name, template_args> {};
struct dot_expression : pegtl::seq<pegtl::string<'d', 't'>, expression, unqualified_name> {};
struct dot_template_expression : pegtl::seq<pegtl::string<'d', 't'>, expression, unqualified_name, template_args> {};
struct arrow_expression : pegtl::seq<pegtl::string<'p', 't'>, expression, unqualified_name> {};
struct arrow_template_expression : pegtl::seq<pegtl::string<'p', 't'>, expression, unqualified_name, template_args> {};
struct dependent_operator_function_expression : pegtl::seq<pegtl::string<'o', 'n'>, operator_name> {};
struct dependent_operator_function_template_expression
    : pegtl::seq<pegtl::string<'o', 'n'>, operator_name, template_args> {};
struct dependent_operator_template_id_expression : pegtl::seq<source_name, template_args> {};
struct sizeof_param_pack_expression : pegtl::seq<pegtl::string<'s', 'Z'>, template_param> {};
struct expression
    : pegtl::sor<trinary_operator_expression, binary_operator_expression, unary_operator_expression, call_expression,
                 conversion_expression, conversion_multiple_expression, sizeof_expression, alignof_expression,
                 template_param, function_param, dependent_name_expression, dependent_template_id_expression,
                 dot_expression, dot_template_expression, arrow_expression, arrow_template_expression,
                 dependent_operator_function_expression, dependent_operator_function_template_expression, source_name,
                 dependent_operator_template_id_expression, sizeof_param_pack_expression, expr_primary> {};

struct hexdigit : pegtl::sor<pegtl::digit, pegtl::string<'a', 'b', 'c', 'd', 'e', 'f'>> {};
struct float_value : pegtl::plus<hexdigit> {};
struct expr_primary_integer : pegtl::seq<pegtl::one<'L'>, type, number, pegtl::one<'E'>> {};
struct expr_primary_floating : pegtl::seq<pegtl::one<'L'>, type, float_value, pegtl::one<'E'>> {};
struct expr_primary_external_name : pegtl::seq<pegtl::one<'L'>, mangled_name, pegtl::one<'E'>> {};
struct expr_primary : pegtl::sor<expr_primary_integer, expr_primary_floating, expr_primary_external_name> {};

struct discriminator_single_digit : pegtl::seq<pegtl::one<'_'>, pegtl::digit> {};
struct discriminator_multiple_digits : pegtl::seq<pegtl::string<'_', '_'>, positive_number, pegtl::one<'_'>> {};
struct discriminator : pegtl::sor<discriminator_single_digit, discriminator_multiple_digits> {};

struct local_name_simple : pegtl::seq<pegtl::one<'Z'>, encoding, pegtl::one<'E'>, pegtl::sor<name, pegtl::one<'s'>>,
                                      pegtl::opt<discriminator>> {};

struct unnamed_type_name_simple : pegtl::seq<pegtl::string<'U', 't'>, positive_number, pegtl::one<'_'>> {};
struct unnamed_type_name : pegtl::sor<unnamed_type_name_simple, closure_type_name> {};

struct lambda_sig : pegtl::seq<pegtl::one<'v'>, pegtl::plus<type>> {};
struct closure_type_name : pegtl::seq<pegtl::string<'U', 'l'>, lambda_sig, pegtl::one<'E'>, number, pegtl::one<'_'>> {};
struct local_name_lambda
    : pegtl::seq<pegtl::one<'Z'>, encoding, pegtl::string<'E', 'd'>, pegtl::opt<number>, pegtl::one<'_'>, name> {};
struct local_name : pegtl::sor<local_name_simple, local_name_lambda> {};

struct data_member_prefix : pegtl::seq<name, pegtl::one<'M'>> {};

struct seq_id : pegtl::plus<pegtl::alnum> {};
struct substitution_simple : pegtl::seq<pegtl::one<'S'>, pegtl::opt<seq_id>, pegtl::one<'_'>> {};
struct substitution_std : pegtl::string<'S', 't'> {};
struct substitution_std_allocator : pegtl::string<'S', 'a'> {};
struct substitution_std_basic_string : pegtl::string<'S', 'b'> {};
struct substitution_std_basic_string_full : pegtl::string<'S', 's'> {};
struct substitution_std_basic_istream : pegtl::string<'S', 'i'> {};
struct substitution_std_basic_ostream : pegtl::string<'S', 'o'> {};
struct substitution_std_basic_iostream : pegtl::string<'S', 'd'> {};
struct substitution
    : pegtl::sor<substitution_simple, substitution_std, substitution_std_allocator, substitution_std_basic_string,
                 substitution_std_basic_string_full, substitution_std_basic_istream, substitution_std_basic_ostream,
                 substitution_std_basic_iostream> {};

struct std_name : pegtl::seq<pegtl::string<'S', 't'>, unqualified_name> {};

template <typename Rule>
struct DemanglerAction : pegtl::nothing<Rule> {};

template <>
struct DemanglerAction<mangled_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("mangled_name");
    }
};
template <>
struct DemanglerAction<encoding> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("encoding");
    }
};
template <>
struct DemanglerAction<function> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("function");
    }
};
template <>
struct DemanglerAction<name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("name");
    }
};
template <>
struct DemanglerAction<template_decl> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_decl");
    }
};
template <>
struct DemanglerAction<unscoped_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unscoped_name");
    }
};
template <>
struct DemanglerAction<std_unqualified_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("std_unqualified_name");
    }
};
template <>
struct DemanglerAction<unscoped_template_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unscoped_template_name");
    }
};
template <>
struct DemanglerAction<nested_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("nested_name");
    }
};
template <>
struct DemanglerAction<prefix> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("prefix");
    }
};
template <>
struct DemanglerAction<template_prefix_with_args> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_prefix_with_args");
    }
};
template <>
struct DemanglerAction<template_prefix> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_prefix");
    }
};
template <>
struct DemanglerAction<unqualified_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unqualified_name");
    }
};
template <>
struct DemanglerAction<source_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        unsigned size = 0;
        auto lengthPrefixedString = in.string_view();
        unsigned prefixLength = 0;
        while (std::isdigit(lengthPrefixedString[prefixLength])) {
            size *= 10;
            size += lengthPrefixedString[prefixLength++];
        }
        state.lastName = state.bag.emplace_back(lengthPrefixedString.substr(prefixLength));
    }
};
template <>
struct DemanglerAction<new_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("new_operator");
    }
};
template <>
struct DemanglerAction<new_array_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("new_array_operator");
    }
};
template <>
struct DemanglerAction<delete_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("delete_operator");
    }
};
template <>
struct DemanglerAction<delete_array_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("delete_array_operator");
    }
};
template <>
struct DemanglerAction<unary_plus_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unary_plus_operator");
    }
};
template <>
struct DemanglerAction<unary_minus_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unary_minus_operator");
    }
};
template <>
struct DemanglerAction<unary_address_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unary_address_operator");
    }
};
template <>
struct DemanglerAction<unary_deference_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unary_deference_operator");
    }
};
template <>
struct DemanglerAction<bitwise_not_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("bitwise_not_operator");
    }
};
template <>
struct DemanglerAction<plus_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("plus_operator");
    }
};
template <>
struct DemanglerAction<minus_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("minus_operator");
    }
};
template <>
struct DemanglerAction<multiply_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("multiply_operator");
    }
};
template <>
struct DemanglerAction<divide_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("divide_operator");
    }
};
template <>
struct DemanglerAction<remainder_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("remainder_operator");
    }
};
template <>
struct DemanglerAction<bitwise_and_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("bitwise_and_operator");
    }
};
template <>
struct DemanglerAction<bitwise_or_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("bitwise_or_operator");
    }
};
template <>
struct DemanglerAction<bitwise_xor_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("bitwise_xor_operator");
    }
};
template <>
struct DemanglerAction<assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("assign_operator");
    }
};
template <>
struct DemanglerAction<plus_assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("plus_assign_operator");
    }
};
template <>
struct DemanglerAction<minus_assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("minus_assign_operator");
    }
};
template <>
struct DemanglerAction<multiply_assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("multiply_assign_operator");
    }
};
template <>
struct DemanglerAction<divide_assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("divide_assign_operator");
    }
};
template <>
struct DemanglerAction<remainder_assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("remainder_assign_operator");
    }
};
template <>
struct DemanglerAction<bitwise_and_assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("bitwise_and_assign_operator");
    }
};
template <>
struct DemanglerAction<bitwise_or_assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("bitwise_or_assign_operator");
    }
};
template <>
struct DemanglerAction<bitwise_xor_assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("bitwise_xor_assign_operator");
    }
};
template <>
struct DemanglerAction<left_shift_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("left_shift_operator");
    }
};
template <>
struct DemanglerAction<right_shift_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("right_shift_operator");
    }
};
template <>
struct DemanglerAction<left_shift_assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("left_shift_assign_operator");
    }
};
template <>
struct DemanglerAction<right_shift_assign_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("right_shift_assign_operator");
    }
};
template <>
struct DemanglerAction<equal_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("equal_operator");
    }
};
template <>
struct DemanglerAction<not_equal_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("not_equal_operator");
    }
};
template <>
struct DemanglerAction<less_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("less_operator");
    }
};
template <>
struct DemanglerAction<greater_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("greater_operator");
    }
};
template <>
struct DemanglerAction<less_equal_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("less_equal_operator");
    }
};
template <>
struct DemanglerAction<greater_equal_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("greater_equal_operator");
    }
};
template <>
struct DemanglerAction<logical_not_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("logical_not_operator");
    }
};
template <>
struct DemanglerAction<logical_and_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("logical_and_operator");
    }
};
template <>
struct DemanglerAction<logical_or_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("logical_or_operator");
    }
};
template <>
struct DemanglerAction<increment_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("increment_operator");
    }
};
template <>
struct DemanglerAction<decrement_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("decrement_operator");
    }
};
template <>
struct DemanglerAction<comma_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("comma_operator");
    }
};
template <>
struct DemanglerAction<arrow_star_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("arrow_star_operator");
    }
};
template <>
struct DemanglerAction<arrow_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("arrow_operator");
    }
};
template <>
struct DemanglerAction<call_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("call_operator");
    }
};
template <>
struct DemanglerAction<index_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("index_operator");
    }
};
template <>
struct DemanglerAction<question_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("question_operator");
    }
};
template <>
struct DemanglerAction<sizeof_type_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("sizeof_type_operator");
    }
};
template <>
struct DemanglerAction<sizeof_expr_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("sizeof_expr_operator");
    }
};
template <>
struct DemanglerAction<alignof_type_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("alignof_type_operator");
    }
};
template <>
struct DemanglerAction<alignof_expr_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("alignof_expr_operator");
    }
};
template <>
struct DemanglerAction<cast_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("cast_operator");
    }
};
template <>
struct DemanglerAction<vendor_extended_operator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("vendor_extended_operator");
    }
};
template <>
struct DemanglerAction<operator_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("operator_name");
    }
};
template <>
struct DemanglerAction<positive_number> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("positive_number");
    }
};
template <>
struct DemanglerAction<number> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("number");
    }
};
template <>
struct DemanglerAction<nv_offset> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("nv_offset");
    }
};
template <>
struct DemanglerAction<v_offset> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("v_offset");
    }
};
template <>
struct DemanglerAction<call_offset> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("call_offset");
    }
};
template <>
struct DemanglerAction<virtual_table> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("virtual_table");
    }
};
template <>
struct DemanglerAction<vtt_structure> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("vtt_structure");
    }
};
template <>
struct DemanglerAction<typeinfo_structure> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("typeinfo_structure");
    }
};
template <>
struct DemanglerAction<typeinfo_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("typeinfo_name");
    }
};
template <>
struct DemanglerAction<guard_variable> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("guard_variable");
    }
};
template <>
struct DemanglerAction<virtual_thunk> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("virtual_thunk");
    }
};
template <>
struct DemanglerAction<virtual_covariant_thunk> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("virtual_covariant_thunk");
    }
};
template <>
struct DemanglerAction<special_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("special_name");
    }
};
template <>
struct DemanglerAction<ctor_dtor_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("ctor_dtor_name");
    }
};
template <>
struct DemanglerAction<template_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_type");
    }
};
template <>
struct DemanglerAction<CV_qualified_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("CV_qualified_type");
    }
};
template <>
struct DemanglerAction<pointer_to_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("pointer_to_type");
    }
};
template <>
struct DemanglerAction<reference_to_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("reference_to_type");
    }
};
template <>
struct DemanglerAction<rvalue_reference_to_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("rvalue_reference_to_type");
    }
};
template <>
struct DemanglerAction<complex_pair_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("complex_pair_type");
    }
};
template <>
struct DemanglerAction<imaginary_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("imaginary_type");
    }
};
template <>
struct DemanglerAction<vendor_extended_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("vendor_extended_type");
    }
};
template <>
struct DemanglerAction<pack_expansion_of_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("pack_expansion_of_type");
    }
};
template <>
struct DemanglerAction<decltype_of_id_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("decltype_of_id_expression");
    }
};
template <>
struct DemanglerAction<decltype_of_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("decltype_of_expression");
    }
};
template <>
struct DemanglerAction<type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("type");
    }
};
template <>
struct DemanglerAction<CV_qualifiers> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("CV_qualifiers");
    }
};
template <>
struct DemanglerAction<void_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("void_type");
    }
};
template <>
struct DemanglerAction<wchar_t_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("wchar_t_type");
    }
};
template <>
struct DemanglerAction<bool_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("bool_type");
    }
};
template <>
struct DemanglerAction<char_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("char_type");
    }
};
template <>
struct DemanglerAction<signed_char_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("signed_char_type");
    }
};
template <>
struct DemanglerAction<unsigned_char_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unsigned_char_type");
    }
};
template <>
struct DemanglerAction<short_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("short_type");
    }
};
template <>
struct DemanglerAction<unsigned_short_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unsigned_short_type");
    }
};
template <>
struct DemanglerAction<int_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("int_type");
    }
};
template <>
struct DemanglerAction<unsigned_int_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unsigned_int_type");
    }
};
template <>
struct DemanglerAction<long_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("long_type");
    }
};
template <>
struct DemanglerAction<unsigned_long_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unsigned_long_type");
    }
};
template <>
struct DemanglerAction<long_long_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("long_long_type");
    }
};
template <>
struct DemanglerAction<unsigned_long_long> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unsigned_long_long");
    }
};
template <>
struct DemanglerAction<int128_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("int128_type");
    }
};
template <>
struct DemanglerAction<unsigned_int128_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unsigned_int128_type");
    }
};
template <>
struct DemanglerAction<float_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("float_type");
    }
};
template <>
struct DemanglerAction<double_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("double_type");
    }
};
template <>
struct DemanglerAction<long_double_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("long_double_type");
    }
};
template <>
struct DemanglerAction<float128_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("float128_type");
    }
};
template <>
struct DemanglerAction<ellipsis> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("ellipsis");
    }
};
template <>
struct DemanglerAction<ieee754_64_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("ieee754_64_type");
    }
};
template <>
struct DemanglerAction<ieee754_128_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("ieee754_128_type");
    }
};
template <>
struct DemanglerAction<ieee754_32_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("ieee754_32_type");
    }
};
template <>
struct DemanglerAction<ieee754_16_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("ieee754_16_type");
    }
};
template <>
struct DemanglerAction<char32_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("char32_type");
    }
};
template <>
struct DemanglerAction<char16_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("char16_type");
    }
};
template <>
struct DemanglerAction<vendor_extended_builtin_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("vendor_extended_builtin_type");
    }
};
template <>
struct DemanglerAction<builtin_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("builtin_type");
    }
};
template <>
struct DemanglerAction<function_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("function_type");
    }
};
template <>
struct DemanglerAction<bare_function_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("bare_function_type");
    }
};
template <>
struct DemanglerAction<array_type_numerical> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("array_type_numerical");
    }
};
template <>
struct DemanglerAction<array_type_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("array_type_expression");
    }
};
template <>
struct DemanglerAction<array_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("array_type");
    }
};
template <>
struct DemanglerAction<pointer_to_member_type> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("pointer_to_member_type");
    }
};
template <>
struct DemanglerAction<template_param> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_param");
    }
};
template <>
struct DemanglerAction<template_template_param> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_template_param");
    }
};
template <>
struct DemanglerAction<function_param> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("function_param");
    }
};
template <>
struct DemanglerAction<template_args> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_args");
    }
};
template <>
struct DemanglerAction<template_arg_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_arg_expression");
    }
};
template <>
struct DemanglerAction<template_arg_pack> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_arg_pack");
    }
};
template <>
struct DemanglerAction<template_pack_expansion> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_pack_expansion");
    }
};
template <>
struct DemanglerAction<template_arg> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("template_arg");
    }
};
template <>
struct DemanglerAction<unary_operator_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unary_operator_expression");
    }
};
template <>
struct DemanglerAction<binary_operator_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("binary_operator_expression");
    }
};
template <>
struct DemanglerAction<trinary_operator_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("trinary_operator_expression");
    }
};
template <>
struct DemanglerAction<call_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("call_expression");
    }
};
template <>
struct DemanglerAction<conversion_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("conversion_expression");
    }
};
template <>
struct DemanglerAction<conversion_multiple_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("conversion_multiple_expression");
    }
};
template <>
struct DemanglerAction<sizeof_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("sizeof_expression");
    }
};
template <>
struct DemanglerAction<alignof_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("alignof_expression");
    }
};
template <>
struct DemanglerAction<dependent_name_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("dependent_name_expression");
    }
};
template <>
struct DemanglerAction<dependent_template_id_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("dependent_template_id_expression");
    }
};
template <>
struct DemanglerAction<dot_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("dot_expression");
    }
};
template <>
struct DemanglerAction<dot_template_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("dot_template_expression");
    }
};
template <>
struct DemanglerAction<arrow_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("arrow_expression");
    }
};
template <>
struct DemanglerAction<arrow_template_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("arrow_template_expression");
    }
};
template <>
struct DemanglerAction<dependent_operator_function_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("dependent_operator_function_expression");
    }
};
template <>
struct DemanglerAction<dependent_operator_function_template_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("dependent_operator_function_template_expression");
    }
};
template <>
struct DemanglerAction<dependent_operator_template_id_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("dependent_operator_template_id_expression");
    }
};
template <>
struct DemanglerAction<sizeof_param_pack_expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("sizeof_param_pack_expression");
    }
};
template <>
struct DemanglerAction<expression> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("expression");
    }
};
template <>
struct DemanglerAction<hexdigit> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("hexdigit");
    }
};
template <>
struct DemanglerAction<float_value> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("float_value");
    }
};
template <>
struct DemanglerAction<expr_primary_integer> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("expr_primary_integer");
    }
};
template <>
struct DemanglerAction<expr_primary_floating> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("expr_primary_floating");
    }
};
template <>
struct DemanglerAction<expr_primary_external_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("expr_primary_external_name");
    }
};
template <>
struct DemanglerAction<expr_primary> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("expr_primary");
    }
};
template <>
struct DemanglerAction<discriminator_single_digit> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("discriminator_single_digit");
    }
};
template <>
struct DemanglerAction<discriminator_multiple_digits> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("discriminator_multiple_digits");
    }
};
template <>
struct DemanglerAction<discriminator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("discriminator");
    }
};
template <>
struct DemanglerAction<local_name_simple> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("local_name_simple");
    }
};
template <>
struct DemanglerAction<unnamed_type_name_simple> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unnamed_type_name_simple");
    }
};
template <>
struct DemanglerAction<unnamed_type_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("unnamed_type_name");
    }
};
template <>
struct DemanglerAction<lambda_sig> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("lambda_sig");
    }
};
template <>
struct DemanglerAction<closure_type_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("closure_type_name");
    }
};
template <>
struct DemanglerAction<local_name_lambda> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("local_name_lambda");
    }
};
template <>
struct DemanglerAction<local_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("local_name");
    }
};
template <>
struct DemanglerAction<data_member_prefix> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("data_member_prefix");
    }
};
template <>
struct DemanglerAction<seq_id> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("seq_id");
    }
};
template <>
struct DemanglerAction<substitution_simple> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("substitution_simple");
    }
};
template <>
struct DemanglerAction<substitution_std> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("substitution_std");
    }
};
template <>
struct DemanglerAction<substitution_std_allocator> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("substitution_std_allocator");
    }
};
template <>
struct DemanglerAction<substitution_std_basic_string> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("substitution_std_basic_string");
    }
};
template <>
struct DemanglerAction<substitution_std_basic_string_full> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("substitution_std_basic_string_full");
    }
};
template <>
struct DemanglerAction<substitution_std_basic_istream> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("substitution_std_basic_istream");
    }
};
template <>
struct DemanglerAction<substitution_std_basic_ostream> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("substitution_std_basic_ostream");
    }
};
template <>
struct DemanglerAction<substitution_std_basic_iostream> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("substitution_std_basic_iostream");
    }
};
template <>
struct DemanglerAction<substitution> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("substitution");
    }
};
template <>
struct DemanglerAction<std_name> {
    template <typename ActionInput>
    static void apply(const ActionInput& in, DemanglerState& state) {
        debugbreak();
        throw Unimplemented("std_name");
    }
};

}  // namespace PCSX::GNUDemangler

template <typename Name>
struct pegtl::analyze_traits<Name, PCSX::GNUDemangler::source_name> : analyze_any_traits<> {};

bool PCSX::GNUDemangler::internalCheck() { return pegtl::analyze<mangled_name>() == 0; }

bool PCSX::GNUDemangler::trace(std::string_view mangled) {
    pegtl::string_input in(mangled, "mangled");
    return pegtl::standard_trace<mangled_name>(in);
}

#include <iostream>

void PCSX::GNUDemangler::printDot(std::string_view mangled) {
    pegtl::string_input in(mangled, "mangled");
    const auto root = pegtl::parse_tree::parse<PCSX::GNUDemangler::mangled_name>(in);
    if (root) {
        pegtl::parse_tree::print_dot(std::cout, *root);
    }
}

std::string PCSX::GNUDemangler::demangle(std::string_view mangled) {
    try {
        DemanglerState state;
        pegtl::string_input in(mangled, "mangled");
        auto result = pegtl::parse<mangled_name, DemanglerAction>(in, state);
        if (result) state.tostring();
    } catch (Unimplemented unimplemented) {
        std::cout << unimplemented.name;
    } catch (...) {
    }
    return std::string(mangled);
}
