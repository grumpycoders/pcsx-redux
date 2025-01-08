/***************************************************************************
 *   Copyright (C) 2025 PCSX-Redux authors                                 *
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

#include "gtest/gtest.h"
#include "support/gnu-c++-demangler.h"

TEST(GNUDemangler, _Z1fv) { EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z1fv"), "f(void)"); }
TEST(GNUDemangler, _Z1fi) { EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z1fi"), "f(int)"); }
TEST(GNUDemangler, _Z3foo3bar) { EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z3foo3bar"), "foo(bar)"); }
TEST(GNUDemangler, _Zrm1XS_) { EXPECT_EQ(PCSX::GNUDemangler::demangle("_Zrm1XS_"), "operator%(X, X)"); }
TEST(GNUDemangler, _ZplR1XS0_) { EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZplR1XS0_"), "operator+(X&, X&)"); }
TEST(GNUDemangler, _ZlsRK1XS1_) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZlsRK1XS1_"), "operator<< (X const&, X const&)");
}
TEST(GNUDemangler, _ZN3FooIA4_iE3barE) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZN3FooIA4_iE3barE"), "Foo<int[4]>::bar");
}
TEST(GNUDemangler, _Z1fIiEvi) { EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z1fIiEvi"), "void f<int>(int)"); }
TEST(GNUDemangler, _Z5firstI3DuoEvS0_) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z5firstI3DuoEvS0_"), "void first<Duo>(Duo)");
}
TEST(GNUDemangler, _Z5firstI3DuoEvT_) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z5firstI3DuoEvT_"), "void first<Duo>(Duo)");
}
TEST(GNUDemangler, _Z3fooIiPFidEiEvv) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z3fooIiPFidEiEvv"), "void foo<int,int(*)(double),int>()");
}
TEST(GNUDemangler, _ZN1N1fE) { EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZN1N1fE"), "N::f"); }
TEST(GNUDemangler, _ZN6System5Sound4beepEv) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZN6System5Sound4beepEv"), "System::Sound::beep()");
}
TEST(GNUDemangler, _ZN5Arena5levelE) { EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZN5Arena5levelE"), "Arena::level"); }
TEST(GNUDemangler, _ZN5StackIiiE5levelE) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZN5StackIiiE5levelE"), "Stack<int, int>::level");
}
TEST(GNUDemangler, _Z1fI1XEvPVN1AIT_E1TE) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z1fI1XEvPVN1AIT_E1TE"), "void f<X>(A<X>::T volatile*)");
}
TEST(GNUDemangler, _ZngILi42EEvN1AIXplT_Li2EEE1TE) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZngILi42EEvN1AIXplT_Li2EEE1TE"), "void operator-<42>(A<(42)+(2)>::T)");
}
TEST(GNUDemangler, _Z4makeI7FactoryiET_IT0_Ev) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z4makeI7FactoryiET_IT0_Ev"), "Factory<int> make<Factory, int>()");
}
TEST(GNUDemangler, _Z3foo5Hello5WorldS0_S_) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z3foo5Hello5WorldS0_S_"), "foo(Hello, World, World, Hello)");
}
TEST(GNUDemangler, _Z3fooPM2ABi) { EXPECT_EQ(PCSX::GNUDemangler::demangle("_Z3fooPM2ABi"), "foo(int AB::**)"); }
TEST(GNUDemangler, _ZlsRSoRKSs) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZlsRSoRKSs"), "operator<<(std::ostream&,std::string const&)");
}
TEST(GNUDemangler, _ZTI7a_class) { EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZTI7a_class"), "typeid(class a_class)"); }
TEST(GNUDemangler, _ZN4PCSX10SystemImplC2ERKNS_9ArgumentsE) {
    EXPECT_EQ(PCSX::GNUDemangler::demangle("_ZN4PCSX10SystemImplC2ERKNS_9ArgumentsE"),
              "PCSX::SystemImpl::SystemImpl(PCSX::Arguments const&)");
}
