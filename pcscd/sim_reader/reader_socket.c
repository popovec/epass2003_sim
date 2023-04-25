/*
    serial.c

    In March 2023, this file was derived from the OsEID project.
    https:/oseid.sourceforge.io
    https://github.com/popovec/oseid

    This is part of epass2003 simulator.

    Copyright (C) 2016-2023 Peter Popovec, popovec.peter@gmail.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    linux serial port I/O for epass2003 simulator

*/

#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <errno.h>
#include <ifdhandler.h>
#include <PCSC/debuglog.h>

#define _XOPEN_SOURCE_EXTENDED 1
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <string.h>
#include <poll.h>

// use EPASS2003_DEBUG value to enable debug
#define  DPRINT(msg...) {char *env_atr = getenv ("EPASS2003_DEBUG"); if (env_atr) { if (atoi(env_atr) & 2 ) fprintf(stderr, msg);}}

#include "reader_socket.h"

int hex2bytes(char *from, int size, uint8_t * to);
// communication timeout in seconds
#define COMM_TIMEOUT 120

static int reader_fd = -1;
int connection_socket = -1;

//=======================================================================================

RESPONSECODE WritePort(DWORD lun, DWORD length, PUCHAR buffer)
{
	int rv;

	if (reader_fd < 0) {
		Log1(PCSC_LOG_DEBUG, "WritePort skipped (no open port)\n");
		return RET_FAIL;
	}

	rv = write(reader_fd, buffer, length);
	if (rv < 0) {
		Log2(PCSC_LOG_CRITICAL, "write error: %s", strerror(errno));
		close(reader_fd);
		reader_fd = -1;
		return RET_FAIL;
	}
	return RET_OK;
}

//=======================================================================================

RESPONSECODE ReadPort(DWORD lun, PDWORD length, PUCHAR buffer)
{
	int rv;
	int i;
	fd_set fdset;
	int fd = reader_fd;
	struct timeval t;

	if (reader_fd < 0) {
		Log1(PCSC_LOG_DEBUG, "ReadPort skipped (no open port)\n");
		return RET_FAIL;
	}
	if (*length == 0)
		return RET_FAIL;

	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	t.tv_sec = COMM_TIMEOUT;
	t.tv_usec = 0;

	i = select(fd + 1, &fdset, NULL, NULL, &t);
	if (i == -1) {
		Log2(PCSC_LOG_CRITICAL, "select: %s", strerror(errno));
		goto err;
	} else if (i == 0) {
		Log2(PCSC_LOG_DEBUG, "Timeout! (%d sec)", COMM_TIMEOUT);
		goto err;
	}
	rv = read(fd, buffer, *length);

	if (rv <= 0) {
		*length = 0;
		Log2(PCSC_LOG_DEBUG, "read error: %s", strerror(errno));
		goto err;
	}
	*length = rv;
	return RET_OK;
 err:
	close(reader_fd);
	reader_fd = -1;
	return RET_FAIL;
}

//=======================================================================================

RESPONSECODE OpenGBP(DWORD lun, LPSTR dev_name)
{
	struct sockaddr_un name;
	int flags;

	Log2(PCSC_LOG_INFO, "OpenGBP name = %s", dev_name);

	if (connection_socket != -1) {
		Log1(PCSC_LOG_DEBUG, "OpenGBP skipped (socket OK)\n");
		return RET_FAIL;
	}
	connection_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (-1 == connection_socket) {
		Log1(PCSC_LOG_DEBUG, "socket error");
		return RET_FAIL;
	}
	umask(0);
	fchmod(connection_socket, 0x1ff);

	memset(&name, 0, sizeof(name));
	name.sun_family = AF_UNIX;
	strncpy(name.sun_path, dev_name, sizeof(name.sun_path) - 1);

	unlink(dev_name);
	if (-1 == bind(connection_socket, (const struct sockaddr *)&name, sizeof(name))) {
		Log1(PCSC_LOG_DEBUG, "bind error");
		return RET_FAIL;
	}
	if (-1 == listen(connection_socket, 1)) {
		Log1(PCSC_LOG_DEBUG, "listen error");
		return RET_FAIL;
	}
	flags = fcntl(connection_socket, F_GETFL);
	if (-1 == flags) {
		Log1(PCSC_LOG_DEBUG, "flags error.");
		return RET_FAIL;
	}
	if (-1 == fcntl(connection_socket, F_SETFL, flags | O_NONBLOCK)) {
		Log1(PCSC_LOG_DEBUG, "flags  set error.");
		return RET_FAIL;
	}
	return RET_OK;
}

//=======================================================================================

RESPONSECODE CloseGBP(DWORD lun)
{
	Log2(PCSC_LOG_INFO, "CloseGBP, channel = %d", lun);

	if (connection_socket == -1) {
		Log1(PCSC_LOG_DEBUG, "CloseGBP skipped (no open port)\n");
		return RET_FAIL;
	}
	if (reader_fd != -1)
		close(reader_fd);
	close(connection_socket);
	reader_fd = -1;
	connection_socket = -1;
	return RET_OK;
}

//=======================================================================================

RESPONSECODE OpenPortByName(DWORD lun, LPSTR dev_name)
{
	Log2(PCSC_LOG_INFO, "OpenPortByName name = %s", dev_name);
	if (OpenGBP(lun, dev_name) != RET_OK) {
		Log1(PCSC_LOG_CRITICAL, "Open failed");
		return IFD_COMMUNICATION_ERROR;
	}
	return IFD_SUCCESS;
}

//=======================================================================================

RESPONSECODE OpenPort(DWORD lun, DWORD channel)
{
	char dev_name[FILENAME_MAX];

	Log3(PCSC_LOG_INFO, "lun=%" PRIu64 " channel = %" PRIu64, lun, channel);
	if (channel != 0)
		return IFD_COMMUNICATION_ERROR;

	sprintf(dev_name, "/run/pcscd/simulated_reader%d", (int)channel);

	return OpenPortByName(lun, dev_name);
}

//=======================================================================================

RESPONSECODE ClosePort(DWORD lun)
{
	Log2(PCSC_LOG_INFO, "ClosePort, lun = %" PRIu64, lun);
	if (CloseGBP(lun) != RET_OK)
		return IFD_COMMUNICATION_ERROR;

	return IFD_SUCCESS;
}

RESPONSECODE IFDHICCPresence(DWORD Lun)
{
	struct pollfd p;
	p.fd = reader_fd;
	p.events = POLLHUP;

	if (Lun)
		return IFD_COMMUNICATION_ERROR;

	if (reader_fd == -1) {
		reader_fd = accept(connection_socket, NULL, NULL);
		if (reader_fd != -1)
			return IFD_ICC_PRESENT;
		return IFD_ICC_NOT_PRESENT;
	}
	if (-1 == poll(&p, 1, 0)) {
		close(reader_fd);
		reader_fd = -1;
		return IFD_ICC_NOT_PRESENT;
	}
	if (p.revents & POLLHUP) {
		reader_fd = -1;
		return IFD_ICC_NOT_PRESENT;
	}
	return IFD_ICC_PRESENT;
}
