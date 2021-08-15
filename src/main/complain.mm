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
