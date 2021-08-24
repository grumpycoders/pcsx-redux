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

#import <Cocoa/Cocoa.h>

extern "C" void Complain(const char* message) {
    NSAlert* alert = [[NSAlert alloc] init];

    [alert setMessageText:@"Fatal Error"];
    [alert setInformativeText:[NSString stringWithCString:message encoding:[NSString defaultCStringEncoding]]];

#if MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12
    [alert setAlertStyle:NSAlertStyleCritical];
#else
    [alert setAlertStyle:NSCriticalAlertStyle];
#endif
    [alert addButtonWithTitle:@"OK"];

    [[alert window] setLevel:NSModalPanelWindowLevel];

    [alert runModal];
    [alert release];
}
