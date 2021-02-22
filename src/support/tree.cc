/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include "support/tree.h"

// This code is basically a mindless implementation of
// "Introduction to Algorithms, 3rd Edition", chapters 12 and 14.

const PCSX::Intrusive::BaseTree::BaseNode* PCSX::Intrusive::BaseTree::next(
    const PCSX::Intrusive::BaseTree::BaseNode* x) const {
    const BaseNode* y;
    y = x->m_right;
    if (y != m_nil) {
        while (y->m_left != m_nil) y = y->m_left;
    } else {
        y = x->m_parent;
        while ((y != m_nil) && (x == y->m_right)) {
            x = y;
            y = y->m_parent;
        }
    }
    return y;
}

const PCSX::Intrusive::BaseTree::BaseNode* PCSX::Intrusive::BaseTree::prev(
    const PCSX::Intrusive::BaseTree::BaseNode* x) const {
    const BaseNode* y;
    y = x->m_left;
    if (y != m_nil) {
        while (y->m_right != m_nil) y = y->m_right;
    } else {
        y = x->m_parent;
        while ((y != m_nil) && (x == y->m_left)) {
            x = y;
            y = y->m_parent;
        }
    }
    return y;
}

PCSX::Intrusive::BaseTree::BaseNode* PCSX::Intrusive::BaseTree::next(PCSX::Intrusive::BaseTree::BaseNode* x) const {
    BaseNode* y;
    y = x->m_right;
    if (y != m_nil) {
        while (y->m_left != m_nil) y = y->m_left;
    } else {
        y = x->m_parent;
        while ((y != m_nil) && (x == y->m_right)) {
            x = y;
            y = y->m_parent;
        }
    }
    return y;
}

PCSX::Intrusive::BaseTree::BaseNode* PCSX::Intrusive::BaseTree::prev(PCSX::Intrusive::BaseTree::BaseNode* x) const {
    BaseNode* y;
    y = x->m_left;
    if (y != m_nil) {
        while (y->m_right != m_nil) y = y->m_right;
    } else {
        y = x->m_parent;
        while ((y != m_nil) && (x == y->m_left)) {
            x = y;
            y = y->m_parent;
        }
    }
    return y;
}

void PCSX::Intrusive::BaseTree::leftRotate(PCSX::Intrusive::BaseTree::BaseNode* const x) {
    BaseNode* const y = x->m_right;
    x->m_right = y->m_left;
    if (y->m_left != m_nil) y->m_left->m_parent = x;
    y->m_parent = x->m_parent;
    if (x->m_parent == m_nil) {
        m_root = y;
    } else if (x == x->m_parent->m_left) {
        x->m_parent->m_left = y;
    } else {
        x->m_parent->m_right = y;
    }
    y->m_left = x;
    x->m_parent = y;
    y->setMax(x);
    x->rebaseMaxToHigh();
    if (x->m_left != m_nil) x->bumpMax(x->m_left);
    if (x->m_right != m_nil) x->bumpMax(x->m_right);
}

void PCSX::Intrusive::BaseTree::rightRotate(PCSX::Intrusive::BaseTree::BaseNode* const x) {
    BaseNode* const y = x->m_left;
    x->m_left = y->m_right;
    if (y->m_right != m_nil) y->m_right->m_parent = x;
    y->m_parent = x->m_parent;
    if (x->m_parent == m_nil) {
        m_root = y;
    } else if (x == x->m_parent->m_right) {
        x->m_parent->m_right = y;
    } else {
        x->m_parent->m_left = y;
    }
    y->m_right = x;
    x->m_parent = y;
    y->setMax(x);
    x->rebaseMaxToHigh();
    if (x->m_left != m_nil) x->bumpMax(x->m_left);
    if (x->m_right != m_nil) x->bumpMax(x->m_right);
}

void PCSX::Intrusive::BaseTree::insertInternal(PCSX::Intrusive::BaseTree::BaseNode* const z) {
    BaseNode* y = m_nil;
    BaseNode* x = m_root;
    while (x != m_nil) {
        y = x;
        y->bumpMax(z);
        if (z->cmp(x) < 0) {
            x = x->m_left;
        } else {
            x = x->m_right;
        }
    }
    z->m_parent = y;
    if (y == m_nil) {
        m_root = z;
    } else if (z->cmp(y) < 0) {
        y->m_left = z;
    } else {
        y->m_right = z;
    }
    z->m_left = m_nil;
    z->m_right = m_nil;
    z->m_color = BaseNode::Color::RED;
    insertFixup(z);
}

void PCSX::Intrusive::BaseTree::insertFixup(PCSX::Intrusive::BaseTree::BaseNode* z) {
    while (z->m_parent->m_color == BaseNode::Color::RED) {
        if (z->m_parent == z->m_parent->m_parent->m_left) {
            BaseNode* y = z->m_parent->m_parent->m_right;
            if (y->m_color == BaseNode::Color::RED) {
                z->m_parent->m_color = BaseNode::Color::BLACK;
                y->m_color = BaseNode::Color::BLACK;
                z = z->m_parent->m_parent;
                z->m_color = BaseNode::Color::RED;
            } else {
                if (z == z->m_parent->m_right) {
                    z = z->m_parent;
                    leftRotate(z);
                }
                z->m_parent->m_color = BaseNode::Color::BLACK;
                z->m_parent->m_parent->m_color = BaseNode::Color::RED;
                rightRotate(z->m_parent->m_parent);
            }
        } else {
            BaseNode* y = z->m_parent->m_parent->m_left;
            if (y->m_color == BaseNode::Color::RED) {
                z->m_parent->m_color = BaseNode::Color::BLACK;
                y->m_color = BaseNode::Color::BLACK;
                z = z->m_parent->m_parent;
                if (z != m_nil) z->m_color = BaseNode::Color::RED;
            } else {
                if (z == z->m_parent->m_left) {
                    z = z->m_parent;
                    rightRotate(z);
                }
                z->m_parent->m_color = BaseNode::Color::BLACK;
                z->m_parent->m_parent->m_color = BaseNode::Color::RED;
                leftRotate(z->m_parent->m_parent);
            }
        }
    }
    m_root->m_color = BaseNode::Color::BLACK;
}

void PCSX::Intrusive::BaseTree::transplant(PCSX::Intrusive::BaseTree::BaseNode* u,
                                           PCSX::Intrusive::BaseTree::BaseNode* v) {
    if (u->m_parent == m_nil) {
        m_root = v;
    } else if (u == u->m_parent->m_left) {
        u->m_parent->m_left = v;
    } else {
        u->m_parent->m_right = v;
    }
    v->m_parent = u->m_parent;
}

void PCSX::Intrusive::BaseTree::deleteInternal(PCSX::Intrusive::BaseTree::BaseNode* const z) {
    BaseNode* y = z;
    BaseNode* x = nullptr;

    auto o = y->m_color;
    if (z->m_left == m_nil) {
        x = z->m_right;
        transplant(z, z->m_right);
    } else if (z->m_right == m_nil) {
        x = z->m_left;
        transplant(z, z->m_left);
    } else {
        y = z->m_right;
        while (y->m_left != m_nil) y = y->m_left;
        o = y->m_color;
        x = y->m_right;
        if (y->m_parent == z) {
            x->m_parent = y;
        } else {
            transplant(y, y->m_right);
            y->m_right = z->m_right;
            y->m_right->m_parent = y;
        }
        transplant(z, y);
        y->m_left = z->m_left;
        y->m_left->m_parent = y;
        y->m_color = z->m_color;
    }
    if (o == BaseNode::Color::BLACK) deleteFixup(x);
}

void PCSX::Intrusive::BaseTree::deleteFixup(PCSX::Intrusive::BaseTree::BaseNode* x) {
    while ((x != m_root) && (x->m_color == BaseNode::Color::BLACK)) {
        if (x == x->m_parent->m_left) {
            BaseNode* w = x->m_parent->m_right;
            if (w->m_color == BaseNode::Color::RED) {
                w->m_color = BaseNode::Color::BLACK;
                x->m_parent->m_color = BaseNode::Color::RED;
                leftRotate(x->m_parent);
                w = x->m_parent->m_right;
            }
            if ((w->m_left->m_color == BaseNode::Color::BLACK) && (w->m_right->m_color == BaseNode::Color::BLACK)) {
                w->m_color = BaseNode::Color::RED;
                x = x->m_parent;
            } else {
                if (w->m_right->m_color == BaseNode::Color::BLACK) {
                    w->m_left->m_color = BaseNode::Color::BLACK;
                    w->m_color = BaseNode::Color::RED;
                    rightRotate(w);
                    w = x->m_parent->m_right;
                }
                w->m_color = x->m_parent->m_color;
                x->m_parent->m_color = BaseNode::Color::BLACK;
                w->m_right->m_color = BaseNode::Color::BLACK;
                leftRotate(x->m_parent);
                x = m_root;
            }
        } else {
            BaseNode* w = x->m_parent->m_left;
            if (w->m_color == BaseNode::Color::RED) {
                w->m_color = BaseNode::Color::BLACK;
                x->m_parent->m_color = BaseNode::Color::RED;
                rightRotate(x->m_parent);
                w = x->m_parent->m_left;
            }
            if ((w->m_right->m_color == BaseNode::Color::BLACK) && (w->m_left->m_color == BaseNode::Color::BLACK)) {
                w->m_color = BaseNode::Color::RED;
                x = x->m_parent;
            } else {
                if (w->m_left->m_color == BaseNode::Color::BLACK) {
                    w->m_right->m_color = BaseNode::Color::BLACK;
                    w->m_color = BaseNode::Color::RED;
                    leftRotate(w);
                    w = x->m_parent->m_left;
                }
                w->m_color = x->m_parent->m_color;
                x->m_parent->m_color = BaseNode::Color::BLACK;
                w->m_left->m_color = BaseNode::Color::BLACK;
                rightRotate(x->m_parent);
                x = m_root;
            }
        }
    }
    x->m_color = BaseNode::Color::BLACK;
}
