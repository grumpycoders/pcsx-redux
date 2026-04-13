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

#include "support/gnu-c++-demangler.h"

#include <cctype>
#include <iostream>
#include <string>
#include <string_view>
#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/analyze.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>
#include <tao/pegtl/contrib/parse_tree_to_dot.hpp>
#include <tao/pegtl/contrib/trace.hpp>
#include <vector>

#include "support/gnu-c++-demangler-grammar.h"
#include "support/gnu-c++-demangler-selector.h"

namespace pegtl = TAO_PEGTL_NAMESPACE;

namespace PCSX::GNUDemangler {

// Tree walker - converts a PEGTL parse tree into a demangled C++ symbol string.
// Maintains a substitution table and template argument table during the walk.
class TreeWalker {
    using node_t = pegtl::parse_tree::node;

    std::vector<std::string> subs;
    std::vector<std::string> tmplArgs;

  public:
    std::string demangle(const node_t& root) {
        if (root.children.empty()) return "";
        return walk(*root.children[0]);
    }

  private:
    static std::string_view extractName(std::string_view sv) {
        size_t i = 0;
        while (i < sv.size() && std::isdigit(sv[i])) i++;
        return sv.substr(i);
    }

    static int parseNumber(std::string_view sv) {
        bool neg = false;
        if (!sv.empty() && sv[0] == 'n') {
            neg = true;
            sv.remove_prefix(1);
        }
        int val = 0;
        for (char c : sv) val = val * 10 + (c - '0');
        return neg ? -val : val;
    }

    static int parseSeqId(std::string_view sv) {
        int result = 0;
        for (char c : sv) {
            result *= 36;
            if (c >= '0' && c <= '9')
                result += c - '0';
            else if (c >= 'A' && c <= 'Z')
                result += c - 'A' + 10;
        }
        return result + 1;
    }

    void addSub(const std::string& s) { subs.push_back(s); }

    int getSubIndex(const node_t& n) {
        if (n.children.empty()) return 0;
        return parseSeqId(n.children[0]->string_view());
    }

    int getTmplIndex(const node_t& n) {
        if (n.children.empty()) return 0;
        return parseNumber(n.children[0]->string_view()) + 1;
    }

    static bool isBuiltinType(const node_t& n) {
        return n.is_type<void_type>() || n.is_type<wchar_t_type>() || n.is_type<bool_type>() ||
               n.is_type<char_type>() || n.is_type<signed_char_type>() || n.is_type<unsigned_char_type>() ||
               n.is_type<short_type>() || n.is_type<unsigned_short_type>() || n.is_type<int_type>() ||
               n.is_type<unsigned_int_type>() || n.is_type<long_type>() || n.is_type<unsigned_long_type>() ||
               n.is_type<long_long_type>() || n.is_type<unsigned_long_long>() || n.is_type<int128_type>() ||
               n.is_type<unsigned_int128_type>() || n.is_type<float_type>() || n.is_type<double_type>() ||
               n.is_type<long_double_type>() || n.is_type<float128_type>() || n.is_type<ellipsis>() ||
               n.is_type<ieee754_64_type>() || n.is_type<ieee754_128_type>() || n.is_type<ieee754_32_type>() ||
               n.is_type<ieee754_16_type>() || n.is_type<char32_type>() || n.is_type<char16_type>() ||
               n.is_type<vendor_extended_builtin_type>();
    }

    static bool isSubRef(const node_t& n) {
        return n.is_type<substitution_simple>() || n.is_type<template_param>();
    }

    static std::string operatorSymbol(const node_t& n) {
        if (n.is_type<new_operator>()) return " new";
        if (n.is_type<new_array_operator>()) return " new[]";
        if (n.is_type<delete_operator>()) return " delete";
        if (n.is_type<delete_array_operator>()) return " delete[]";
        if (n.is_type<unary_plus_operator>() || n.is_type<plus_operator>()) return "+";
        if (n.is_type<unary_minus_operator>() || n.is_type<minus_operator>()) return "-";
        if (n.is_type<unary_address_operator>() || n.is_type<bitwise_and_operator>()) return "&";
        if (n.is_type<unary_deference_operator>() || n.is_type<multiply_operator>()) return "*";
        if (n.is_type<bitwise_not_operator>()) return "~";
        if (n.is_type<divide_operator>()) return "/";
        if (n.is_type<remainder_operator>()) return "%";
        if (n.is_type<bitwise_or_operator>()) return "|";
        if (n.is_type<bitwise_xor_operator>()) return "^";
        if (n.is_type<assign_operator>()) return "=";
        if (n.is_type<plus_assign_operator>()) return "+=";
        if (n.is_type<minus_assign_operator>()) return "-=";
        if (n.is_type<multiply_assign_operator>()) return "*=";
        if (n.is_type<divide_assign_operator>()) return "/=";
        if (n.is_type<remainder_assign_operator>()) return "%=";
        if (n.is_type<bitwise_and_assign_operator>()) return "&=";
        if (n.is_type<bitwise_or_assign_operator>()) return "|=";
        if (n.is_type<bitwise_xor_assign_operator>()) return "^=";
        if (n.is_type<left_shift_operator>()) return "<<";
        if (n.is_type<right_shift_operator>()) return ">>";
        if (n.is_type<left_shift_assign_operator>()) return "<<=";
        if (n.is_type<right_shift_assign_operator>()) return ">>=";
        if (n.is_type<equal_operator>()) return "==";
        if (n.is_type<not_equal_operator>()) return "!=";
        if (n.is_type<less_operator>()) return "<";
        if (n.is_type<greater_operator>()) return ">";
        if (n.is_type<less_equal_operator>()) return "<=";
        if (n.is_type<greater_equal_operator>()) return ">=";
        if (n.is_type<logical_not_operator>()) return "!";
        if (n.is_type<logical_and_operator>()) return "&&";
        if (n.is_type<logical_or_operator>()) return "||";
        if (n.is_type<increment_operator>()) return "++";
        if (n.is_type<decrement_operator>()) return "--";
        if (n.is_type<comma_operator>()) return ",";
        if (n.is_type<arrow_star_operator>()) return "->*";
        if (n.is_type<arrow_operator>()) return "->";
        if (n.is_type<call_operator>()) return "()";
        if (n.is_type<index_operator>()) return "[]";
        if (n.is_type<question_operator>()) return "?";
        if (n.is_type<sizeof_type_operator>()) return "sizeof";
        if (n.is_type<sizeof_expr_operator>()) return "sizeof";
        if (n.is_type<alignof_type_operator>()) return "alignof";
        if (n.is_type<alignof_expr_operator>()) return "alignof";
        return "??";
    }

    static bool isOperator(const node_t& n) {
        return n.is_type<new_operator>() || n.is_type<new_array_operator>() || n.is_type<delete_operator>() ||
               n.is_type<delete_array_operator>() || n.is_type<unary_plus_operator>() ||
               n.is_type<unary_minus_operator>() || n.is_type<unary_address_operator>() ||
               n.is_type<unary_deference_operator>() || n.is_type<bitwise_not_operator>() ||
               n.is_type<plus_operator>() || n.is_type<minus_operator>() || n.is_type<multiply_operator>() ||
               n.is_type<divide_operator>() || n.is_type<remainder_operator>() ||
               n.is_type<bitwise_and_operator>() || n.is_type<bitwise_or_operator>() ||
               n.is_type<bitwise_xor_operator>() || n.is_type<assign_operator>() ||
               n.is_type<plus_assign_operator>() || n.is_type<minus_assign_operator>() ||
               n.is_type<multiply_assign_operator>() || n.is_type<divide_assign_operator>() ||
               n.is_type<remainder_assign_operator>() || n.is_type<bitwise_and_assign_operator>() ||
               n.is_type<bitwise_or_assign_operator>() || n.is_type<bitwise_xor_assign_operator>() ||
               n.is_type<left_shift_operator>() || n.is_type<right_shift_operator>() ||
               n.is_type<left_shift_assign_operator>() || n.is_type<right_shift_assign_operator>() ||
               n.is_type<equal_operator>() || n.is_type<not_equal_operator>() || n.is_type<less_operator>() ||
               n.is_type<greater_operator>() || n.is_type<less_equal_operator>() ||
               n.is_type<greater_equal_operator>() || n.is_type<logical_not_operator>() ||
               n.is_type<logical_and_operator>() || n.is_type<logical_or_operator>() ||
               n.is_type<increment_operator>() || n.is_type<decrement_operator>() ||
               n.is_type<comma_operator>() || n.is_type<arrow_star_operator>() || n.is_type<arrow_operator>() ||
               n.is_type<call_operator>() || n.is_type<index_operator>() || n.is_type<question_operator>() ||
               n.is_type<sizeof_type_operator>() || n.is_type<sizeof_expr_operator>() ||
               n.is_type<alignof_type_operator>() || n.is_type<alignof_expr_operator>() ||
               n.is_type<cast_operator>();
    }

    static std::string builtinName(const node_t& n) {
        if (n.is_type<void_type>()) return "void";
        if (n.is_type<wchar_t_type>()) return "wchar_t";
        if (n.is_type<bool_type>()) return "bool";
        if (n.is_type<char_type>()) return "char";
        if (n.is_type<signed_char_type>()) return "signed char";
        if (n.is_type<unsigned_char_type>()) return "unsigned char";
        if (n.is_type<short_type>()) return "short";
        if (n.is_type<unsigned_short_type>()) return "unsigned short";
        if (n.is_type<int_type>()) return "int";
        if (n.is_type<unsigned_int_type>()) return "unsigned int";
        if (n.is_type<long_type>()) return "long";
        if (n.is_type<unsigned_long_type>()) return "unsigned long";
        if (n.is_type<long_long_type>()) return "long long";
        if (n.is_type<unsigned_long_long>()) return "unsigned long long";
        if (n.is_type<int128_type>()) return "__int128";
        if (n.is_type<unsigned_int128_type>()) return "unsigned __int128";
        if (n.is_type<float_type>()) return "float";
        if (n.is_type<double_type>()) return "double";
        if (n.is_type<long_double_type>()) return "long double";
        if (n.is_type<float128_type>()) return "__float128";
        if (n.is_type<ellipsis>()) return "...";
        if (n.is_type<ieee754_64_type>()) return "decimal64";
        if (n.is_type<ieee754_128_type>()) return "decimal128";
        if (n.is_type<ieee754_32_type>()) return "decimal32";
        if (n.is_type<ieee754_16_type>()) return "_Float16";
        if (n.is_type<char32_type>()) return "char32_t";
        if (n.is_type<char16_type>()) return "char16_t";
        if (n.is_type<vendor_extended_builtin_type>()) {
            return std::string(extractName(n.children[0]->string_view()));
        }
        return "??";
    }

    static std::string namedSubstitution(const node_t& n) {
        if (n.is_type<substitution_std>()) return "std";
        if (n.is_type<substitution_std_allocator>()) return "std::allocator";
        if (n.is_type<substitution_std_basic_string>()) return "std::basic_string";
        if (n.is_type<substitution_std_basic_string_full>()) return "std::string";
        if (n.is_type<substitution_std_basic_istream>()) return "std::istream";
        if (n.is_type<substitution_std_basic_ostream>()) return "std::ostream";
        if (n.is_type<substitution_std_basic_iostream>()) return "std::iostream";
        return "??";
    }

    static bool isNamedSubstitution(const node_t& n) {
        return n.is_type<substitution_std>() || n.is_type<substitution_std_allocator>() ||
               n.is_type<substitution_std_basic_string>() || n.is_type<substitution_std_basic_string_full>() ||
               n.is_type<substitution_std_basic_istream>() || n.is_type<substitution_std_basic_ostream>() ||
               n.is_type<substitution_std_basic_iostream>();
    }

    static std::string cvString(const node_t& n) {
        std::string result;
        auto sv = n.string_view();
        for (char c : sv) {
            if (c == 'r') result += " restrict";
            if (c == 'V') result += " volatile";
            if (c == 'K') result += " const";
        }
        return result;
    }

    static bool isVoidArgs(const node_t& bft, size_t startIdx) {
        if (bft.children.size() - startIdx != 1) return false;
        return bft.children[startIdx]->is_type<void_type>();
    }

    std::string formatArgs(const node_t& bft, size_t startIdx) {
        if (isVoidArgs(bft, startIdx)) return "";
        std::string result;
        for (size_t i = startIdx; i < bft.children.size(); i++) {
            if (i > startIdx) result += ", ";
            result += walkAsType(*bft.children[i]);
        }
        return result;
    }

    std::string walkAsType(const node_t& n) {
        std::string result = walk(n);
        if (!isBuiltinType(n) && !isSubRef(n)) {
            addSub(result);
        }
        return result;
    }

    std::string formatFuncPtrRef(const node_t& funcType, const std::string& modifier) {
        auto& bft = *funcType.children[0];
        std::string retType = walkAsType(*bft.children[0]);
        std::string args = formatArgs(bft, 1);
        return retType + " (" + modifier + ")(" + args + ")";
    }

    // Main dispatch
    std::string walk(const node_t& n) {
        if (n.is_root()) return demangle(n);

        if (n.is_type<source_name>()) return std::string(extractName(n.string_view()));
        if (isBuiltinType(n)) return builtinName(n);

        if (isOperator(n)) {
            if (n.is_type<cast_operator>()) return "operator " + walk(*n.children[0]);
            return "operator" + operatorSymbol(n);
        }

        if (n.is_type<function>()) return walkFunction(n);
        if (n.is_type<nested_name>()) return walkNestedName(n);
        if (n.is_type<template_decl>()) return walkTemplateDecl(n);
        if (n.is_type<template_args>()) return walkTemplateArgs(n);
        if (n.is_type<bare_function_type>()) return "??";

        if (n.is_type<CV_qualified_type>()) {
            return walkAsType(*n.children[1]) + cvString(*n.children[0]);
        }

        if (n.is_type<pointer_to_type>()) {
            auto& inner = *n.children[0];
            if (inner.is_type<function_type>()) return formatFuncPtrRef(inner, "*");
            return walkAsType(inner) + "*";
        }

        if (n.is_type<reference_to_type>()) {
            auto& inner = *n.children[0];
            if (inner.is_type<function_type>()) return formatFuncPtrRef(inner, "&");
            return walkAsType(inner) + "&";
        }

        if (n.is_type<rvalue_reference_to_type>()) return walkAsType(*n.children[0]) + "&&";

        if (n.is_type<function_type>()) {
            auto& bft = *n.children[0];
            return walkAsType(*bft.children[0]) + "(" + formatArgs(bft, 1) + ")";
        }

        if (n.is_type<array_type_numerical>()) {
            return walkAsType(*n.children[1]) + "[" + std::string(n.children[0]->string_view()) + "]";
        }
        if (n.is_type<array_type_expression>()) return walkAsType(*n.children.back()) + "[]";

        if (n.is_type<pointer_to_member_type>()) {
            return walkAsType(*n.children[1]) + " " + walkAsType(*n.children[0]) + "::*";
        }

        if (n.is_type<substitution_simple>()) {
            int idx = getSubIndex(n);
            if (idx >= 0 && idx < (int)subs.size()) return subs[idx];
            return "{sub(" + std::to_string(idx) + ")}";
        }

        if (isNamedSubstitution(n)) {
            std::string result = namedSubstitution(n);
            addSub(result);
            return result;
        }

        if (n.is_type<template_param>()) {
            int idx = getTmplIndex(n);
            if (idx >= 0 && idx < (int)tmplArgs.size()) return tmplArgs[idx];
            return "{tmpl(" + std::to_string(idx) + ")}";
        }

        // Template arg pack: J arg* E - expand the args inline
        if (n.is_type<template_arg_pack>()) {
            std::string result;
            for (size_t i = 0; i < n.children.size(); i++) {
                if (i > 0) result += ", ";
                result += walkAsType(*n.children[i]);
            }
            return result;
        }

        // Pack expansion: Dp type
        if (n.is_type<pack_expansion_of_type>()) {
            return walkAsType(*n.children[0]);
        }

        if (n.is_type<template_type>()) return walk(*n.children[0]) + walk(*n.children[1]);
        if (n.is_type<template_prefix_with_args>()) return walk(*n.children[0]) + walk(*n.children[1]);
        if (n.is_type<std_unqualified_name>()) return "std::" + walk(*n.children[0]);
        if (n.is_type<std_name>()) return "std::" + walk(*n.children[0]);
        if (n.is_type<ctor_dtor_name>()) return std::string(n.string_view());

        if (n.is_type<virtual_table>()) return "vtable for " + walk(*n.children[0]);
        if (n.is_type<vtt_structure>()) return "VTT for " + walk(*n.children[0]);
        if (n.is_type<typeinfo_structure>()) return "typeinfo for " + walk(*n.children[0]);
        if (n.is_type<typeinfo_name>()) return "typeinfo name for " + walk(*n.children[0]);
        if (n.is_type<guard_variable>()) return "guard variable for " + walk(*n.children[0]);

        if (n.is_type<local_name_simple>()) return walk(*n.children[0]) + "::" + walk(*n.children[1]);

        if (n.is_type<closure_type_name>()) {
            // Children: lambda_sig types..., optionally a number (discriminator)
            // Format: {lambda(param_types)#N}
            std::string params;
            int discrim = 1;
            for (auto& child : n.children) {
                if (child->is_type<number>()) {
                    discrim = parseNumber(child->string_view()) + 2;
                } else if (child->is_type<void_type>()) {
                    // void param means no params
                } else {
                    if (!params.empty()) params += ", ";
                    params += walkAsType(*child);
                }
            }
            return "{lambda(" + params + ")#" + std::to_string(discrim) + "}";
        }

        if (n.is_type<expr_primary_integer>()) {
            if (n.children.size() >= 2) return std::string(n.children[1]->string_view());
            return "??";
        }

        if (n.is_type<template_arg_expression>()) {
            if (!n.children.empty()) return walk(*n.children[0]);
            return "??";
        }

        if (n.is_type<binary_operator_expression>()) {
            if (n.children.size() >= 3) {
                return "(" + walk(*n.children[1]) + ")" + operatorSymbol(*n.children[0]) + "(" +
                       walk(*n.children[2]) + ")";
            }
            return "??";
        }

        if (n.is_type<unary_operator_expression>()) {
            if (n.children.size() >= 2) {
                return operatorSymbol(*n.children[0]) + "(" + walk(*n.children[1]) + ")";
            }
            return "??";
        }

        if (n.is_type<positive_number>() || n.is_type<number>()) return std::string(n.string_view());
        if (n.is_type<data_member_prefix>()) return walk(*n.children[0]);
        if (n.is_type<CV_qualifiers>()) return cvString(n);

        // Fallback
        if (!n.children.empty()) {
            std::string result;
            for (auto& child : n.children) result += walk(*child);
            return result;
        }
        return "??";
    }

    // Check if a nested_name represents a template function (last component has template_args)
    static bool nestedNameIsTemplate(const node_t& n) {
        for (auto it = n.children.rbegin(); it != n.children.rend(); ++it) {
            if ((*it)->is_type<CV_qualifiers>()) continue;
            return (*it)->is_type<template_args>();
        }
        return false;
    }

    std::string walkFunction(const node_t& n) {
        auto& nameNode = *n.children[0];
        auto& bft = *n.children[1];

        bool isTemplate = nameNode.is_type<template_decl>() ||
                          (nameNode.is_type<nested_name>() && nestedNameIsTemplate(nameNode));

        std::string funcName;
        std::string memberCV;
        if (nameNode.is_type<template_decl>()) {
            funcName = walkTemplateDecl(nameNode);
        } else if (nameNode.is_type<nested_name>()) {
            funcName = walkNestedName(nameNode, isTemplate, &memberCV);
        } else if (nameNode.is_type<local_name_simple>()) {
            funcName = walkLocalNameForFunction(nameNode, &memberCV);
        } else {
            funcName = walkFuncName(nameNode);
        }

        std::string retType;
        size_t argStart = 0;
        if (isTemplate) {
            retType = walkAsType(*bft.children[0]);
            argStart = 1;
        }

        std::string args = formatArgs(bft, argStart);
        std::string result;
        if (!retType.empty())
            result = retType + " " + funcName + "(" + args + ")" + memberCV;
        else
            result = funcName + "(" + args + ")" + memberCV;
        return result;
    }

    std::string walkLocalNameForFunction(const node_t& n, std::string* outMemberCV) {
        // local_name_simple children: [encoding_result, local_entity_name]
        // If the local entity is a nested_name with CV, extract the CV for the function
        std::string enc = walk(*n.children[0]);
        std::string local;
        if (n.children.size() >= 2 && n.children[1]->is_type<nested_name>()) {
            local = walkNestedName(*n.children[1], false, outMemberCV);
        } else if (n.children.size() >= 2) {
            local = walk(*n.children[1]);
        }
        return enc + "::" + local;
    }

    std::string walkFuncName(const node_t& n) {
        if (isOperator(n)) {
            if (n.is_type<cast_operator>()) return "operator " + walk(*n.children[0]);
            return "operator" + operatorSymbol(n);
        }
        return walk(n);
    }

    std::string walkNestedName(const node_t& n, bool populateTmplArgs = false,
                               std::string* outMemberCV = nullptr) {
        std::string result;
        std::string lastSourceName;
        std::string cvSuffix;
        bool needsSep = false;
        std::string cumulative;

        for (auto& child : n.children) {
            if (child->is_type<CV_qualifiers>()) {
                cvSuffix = cvString(*child);
                continue;
            }
            if (child->is_type<template_args>()) {
                if (populateTmplArgs) {
                    // Populate tmplArgs for T_ resolution in function signatures.
                    // Only the last template_args matters, so clear each time.
                    tmplArgs.clear();
                    std::string args = "<";
                    for (size_t i = 0; i < child->children.size(); i++) {
                        if (i > 0) args += ", ";
                        auto& targ = *child->children[i];
                        std::string argStr;
                        if (targ.is_type<expr_primary_integer>() || targ.is_type<template_arg_expression>() ||
                            targ.is_type<binary_operator_expression>() ||
                            targ.is_type<unary_operator_expression>()) {
                            argStr = walk(targ);
                        } else {
                            argStr = walkAsType(targ);
                        }
                        tmplArgs.push_back(argStr);
                        args += argStr;
                    }
                    args += ">";
                    result += args;
                    cumulative += args;
                    addSub(cumulative);
                } else {
                    std::string args = walkTemplateArgs(*child);
                    result += args;
                    cumulative += args;
                    addSub(cumulative);
                }
                continue;
            }

            std::string component;
            if (child->is_type<ctor_dtor_name>()) {
                component = (child->string_view()[0] == 'C') ? lastSourceName : "~" + lastSourceName;
            } else if (child->is_type<substitution_simple>()) {
                int idx = getSubIndex(*child);
                component = (idx >= 0 && idx < (int)subs.size()) ? subs[idx]
                                                                  : "{sub(" + std::to_string(idx) + ")}";
            } else if (isNamedSubstitution(*child)) {
                component = namedSubstitution(*child);
                addSub(component);
            } else if (child->is_type<template_param>()) {
                int idx = getTmplIndex(*child);
                component = (idx >= 0 && idx < (int)tmplArgs.size()) ? tmplArgs[idx]
                                                                      : "{tmpl(" + std::to_string(idx) + ")}";
            } else if (child->is_type<template_prefix_with_args>()) {
                component = walk(*child);
            } else if (child->is_type<source_name>()) {
                component = std::string(extractName(child->string_view()));
                lastSourceName = component;
            } else {
                component = walk(*child);
            }

            if (needsSep) {
                result += "::";
                cumulative += "::";
            }
            result += component;
            cumulative += component;
            needsSep = true;
            addSub(cumulative);
        }

        if (outMemberCV)
            *outMemberCV = cvSuffix;
        else
            result += cvSuffix;
        return result;
    }

    std::string walkTemplateDecl(const node_t& n) {
        std::string tmplName = walkFuncName(*n.children[0]);
        addSub(tmplName);

        auto& argsNode = *n.children[1];
        std::vector<std::string> savedArgs;
        std::swap(tmplArgs, savedArgs);

        std::string argsStr = "<";
        for (size_t i = 0; i < argsNode.children.size(); i++) {
            if (i > 0) argsStr += ", ";
            auto& child = *argsNode.children[i];
            std::string arg;
            if (child.is_type<expr_primary_integer>() || child.is_type<template_arg_expression>() ||
                child.is_type<binary_operator_expression>() || child.is_type<unary_operator_expression>()) {
                arg = walk(child);
            } else {
                arg = walkAsType(child);
            }
            tmplArgs.push_back(arg);
            argsStr += arg;
        }
        argsStr += ">";
        return tmplName + argsStr;
    }

    std::string walkTemplateArgs(const node_t& n) {
        std::string result = "<";
        for (size_t i = 0; i < n.children.size(); i++) {
            if (i > 0) result += ", ";
            auto& child = *n.children[i];
            if (child.is_type<expr_primary_integer>() || child.is_type<template_arg_expression>() ||
                child.is_type<binary_operator_expression>() || child.is_type<unary_operator_expression>() ||
                child.is_type<trinary_operator_expression>()) {
                result += walk(child);
            } else {
                result += walkAsType(child);
            }
        }
        result += ">";
        return result;
    }
};

}  // namespace PCSX::GNUDemangler

bool PCSX::GNUDemangler::internalCheck() { return pegtl::analyze<mangled_name>() == 0; }

bool PCSX::GNUDemangler::trace(std::string_view mangled) {
    pegtl::string_input in(mangled, "mangled");
    return pegtl::standard_trace<mangled_name>(in);
}

void PCSX::GNUDemangler::printDot(std::string_view mangled) {
    pegtl::string_input in(mangled, "mangled");
    const auto root = pegtl::parse_tree::parse<mangled_name>(in);
    if (root) {
        pegtl::parse_tree::print_dot(std::cout, *root);
    }
}

std::string PCSX::GNUDemangler::demangle(std::string_view mangled) {
    // GCC global constructor/destructor wrappers
    static constexpr std::string_view globalCtorPrefix = "_GLOBAL__sub_I_";
    static constexpr std::string_view globalDtorPrefix = "_GLOBAL__sub_D_";
    if (mangled.size() > globalCtorPrefix.size() &&
        mangled.substr(0, globalCtorPrefix.size()) == globalCtorPrefix) {
        return "global constructors keyed to " + demangle(mangled.substr(globalCtorPrefix.size()));
    }
    if (mangled.size() > globalDtorPrefix.size() &&
        mangled.substr(0, globalDtorPrefix.size()) == globalDtorPrefix) {
        return "global destructors keyed to " + demangle(mangled.substr(globalDtorPrefix.size()));
    }
    if (mangled.size() < 2 || mangled[0] != '_' || mangled[1] != 'Z') {
        return std::string(mangled);
    }
    try {
        pegtl::string_input in(mangled, "mangled");
        if (auto root = pegtl::parse_tree::parse<mangled_name, DemanglerSelector>(in)) {
            return TreeWalker().demangle(*root);
        }
    } catch (...) {
    }
    // If full parse failed, try truncating at '.' from the right (GCC extension suffixes like .actor)
    auto dot = mangled.rfind('.');
    while (dot != std::string_view::npos && dot > 2) {
        std::string prefix = demangle(mangled.substr(0, dot));
        if (prefix != mangled.substr(0, dot)) {
            return prefix + " [" + std::string(mangled.substr(dot + 1)) + "]";
        }
        dot = mangled.rfind('.', dot - 1);
    }
    return std::string(mangled);
}
