/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# ANSI C "string.h" for PS1.
#
*/

#ifndef _STRING_H
#define _STRING_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void* memcpy(void* dest, const void* src, size_t n);
void* memmove(void* dest, const void* src, size_t n);
void* memchr(const void* s, char c, size_t n);
int memcmp(const void* s1, const void* s2, size_t n);
void* memset(void*, int, size_t);
char* strcat(char* dest, const char* src);
char* strncat(char*, const char*, size_t);
char* strchr(const char*, int);
char* strrchr(const char*, int);
int strcmp(const char*, const char*);
int strncmp(const char*, const char*, size_t);
int strcoll(const char*, const char*);
char* strcpy(char* toHere, const char* fromHere);
char* strncpy(char* toHere, const char* fromHere, size_t);
char* strerror(int);
size_t strlen(const char*);
size_t strspn(const char* s, const char* accept);
size_t strcspn(const char* s, const char* reject);
char* strpbrk(const char* s, const char* accept);
char* strstr(const char* haystack, const char* needle);
char* strtok(char*, const char*);
size_t strxfrm(char* dest, const char* src, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* _STRING_H */
