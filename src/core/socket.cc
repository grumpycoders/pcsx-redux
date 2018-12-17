/*  Pcsx - Pc Psx Emulator
 *  Copyright (C) 1999-2003  Pcsx Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses>.
 */

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "core/psxemulator.h"
#include "core/socket.h"

#ifndef _WIN32
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef _WIN32
static SOCKET s_server_socket = 0;
static SOCKET s_client_socket = 0;
#else
static int s_server_socket = 0;
static int s_client_socket = 0;
#endif

static char s_tbuf[513];
static int s_ptr = 0;

#define PORT_NUMBER 12345

int StartServer() {
    struct in_addr localhostaddr;
    struct sockaddr_in localsocketaddr;

#ifdef _WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) return -1;
#endif

    s_server_socket = socket(AF_INET, SOCK_STREAM, 0);

#ifdef _WIN32
    if (s_server_socket == INVALID_SOCKET) return -1;
#else
    if (s_server_socket == -1) return -1;
#endif

    SetsNonblock();

    memset((void *)&localhostaddr, 0, sizeof(localhostaddr));
    memset(&localsocketaddr, 0, sizeof(struct sockaddr_in));

#ifdef _WIN32
    localhostaddr.S_un.S_addr = htonl(INADDR_ANY);
#else
    localhostaddr.s_addr = htonl(INADDR_ANY);
#endif
    localsocketaddr.sin_family = AF_INET;
    localsocketaddr.sin_addr = localhostaddr;
    localsocketaddr.sin_port = htons(PORT_NUMBER);

    if (bind(s_server_socket, (struct sockaddr *)&localsocketaddr, sizeof(localsocketaddr)) < 0) return -1;

    if (listen(s_server_socket, 1) != 0) return -1;

    return 0;
}

void StopServer() {
#ifdef _WIN32
    shutdown(s_server_socket, SD_BOTH);
    closesocket(s_server_socket);
    WSACleanup();
#else
    shutdown(s_server_socket, SHUT_RDWR);
    close(s_server_socket);
#endif
}

void GetClient() {
    int new_socket;
    char hello[256];

    new_socket = accept(s_server_socket, 0, 0);

#ifdef _WIN32
    if (new_socket == INVALID_SOCKET) return;
#else
    if (new_socket == -1) return;
#endif
    if (s_client_socket) CloseClient();
    s_client_socket = new_socket;

#ifndef _WIN32
    {
        int flags;
        flags = fcntl(s_client_socket, F_GETFL, 0);
        fcntl(s_client_socket, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    sprintf(hello, "000 PCSXR Version %s - Debug console\r\n", PACKAGE_VERSION);
    WriteSocket(hello, strlen(hello));
    s_ptr = 0;
}

void CloseClient() {
    if (s_client_socket) {
#ifdef _WIN32
        shutdown(s_client_socket, SD_BOTH);
        closesocket(s_client_socket);
#else
        shutdown(s_client_socket, SHUT_RDWR);
        close(s_client_socket);
#endif
        s_client_socket = 0;
    }
}

int HasClient() { return s_client_socket ? 1 : 0; }

int ReadSocket(char *buffer, int len) {
    int r;
    char *endl;

    if (!s_client_socket) return -1;

    r = recv(s_client_socket, s_tbuf + s_ptr, 512 - s_ptr, 0);

    if (r == 0) {
        s_client_socket = 0;
        if (!s_ptr) return 0;
    }
#ifdef _WIN32
    if (r == SOCKET_ERROR)
#else
    if (r == -1)
#endif
    {
        if (s_ptr == 0) return -1;
        r = 0;
    }
    s_ptr += r;
    s_tbuf[s_ptr] = 0;

    endl = strstr(s_tbuf, "\r\n");

    if (endl) {
        r = endl - s_tbuf;
        strncpy(buffer, s_tbuf, r);

        r += 2;
        memmove(s_tbuf, s_tbuf + r, 512 - r);
        s_ptr -= r;
        memset(s_tbuf + r, 0, 512 - r);
        r -= 2;

    } else {
        r = 0;
    }

    buffer[r] = 0;

    return r;
}

int RawReadSocket(char *buffer, int len) {
    int r = 0;
    int mlen = len < s_ptr ? len : s_ptr;

    if (!s_client_socket) return -1;

    if (s_ptr) {
        memcpy(buffer, s_tbuf, mlen);
        s_ptr -= mlen;
        memmove(s_tbuf, s_tbuf + mlen, 512 - mlen);
    }

    if (len - mlen) r = recv(s_client_socket, buffer + mlen, len - mlen, 0);

    if (r == 0) {
        s_client_socket = 0;
        if (!s_ptr) return 0;
    }
#ifdef _WIN32
    if (r == SOCKET_ERROR)
#else
    if (r == -1)
#endif
    {
        if (s_ptr == 0) return -1;
        r = 0;
    }

    r += mlen;

    return r;
}

void WriteSocket(char *buffer, int len) {
    if (!s_client_socket) return;

    send(s_client_socket, buffer, len, 0);
}

void SetsBlock() {
#ifdef _WIN32
    u_long b = 0;
    ioctlsocket(s_server_socket, FIONBIO, &b);
#else
    int flags = fcntl(s_server_socket, F_GETFL, 0);
    fcntl(s_server_socket, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

void SetsNonblock() {
#ifdef _WIN32
    u_long b = 1;
    ioctlsocket(s_server_socket, FIONBIO, &b);
#else
    int flags = fcntl(s_server_socket, F_GETFL, 0);
    fcntl(s_server_socket, F_SETFL, flags | O_NONBLOCK);
#endif
}
