#ifndef _RECORD_H_
#define _RECORD_H_

#ifdef _WIN32
void RecordStart();
void RecordBuffer(unsigned char* pSound, long lBytes);
void RecordStop();
BOOL RecordDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam);
#endif

#endif
