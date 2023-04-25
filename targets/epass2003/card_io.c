/*
    card_io.c

    In March 2023, this file was derived from the OsEID project.
    https:/oseid.sourceforge.io
    https://github.com/popovec/oseid

    This is part of epass2003 simulator.
    
    Copyright (C) 2023 Peter Popovec, popovec.peter@gmail.com

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

    input/output subsystem for OsEID - debug console version

*/

#define DEBUG_IFH
#include "debug.h"

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <setjmp.h>
#include "card_io.h"
#include <sys/socket.h>
#include <sys/un.h>

uint8_t pps;

int data_socket = -1;
struct sockaddr_un addr;
#define SOCKET_NAME "/run/pcscd/simulated_reader0"
void card_io_init(void)
{
	int ret;
	if (data_socket == -1) {
		data_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		if (data_socket == -1) {
			perror("socket");
			exit(EXIT_FAILURE);
		}

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
		ret = connect(data_socket, (const struct sockaddr *)&addr, sizeof(addr));
		if (ret == -1) {
			fprintf(stderr, "The server is down.\n");
			exit(EXIT_FAILURE);
		}
	} else {
#if 0
// if token is uninitialized
		if (-1 == write(data_socket,
				"<  3b:9f:95:81:31:fe:9f:00:66:46:53:05:01:00:11:71:df:00:00:03:6a:82:f8\n",
				71))
			exit(EXIT_FAILURE);
#else
		if (-1 == write(data_socket,
				"<  3b:9f:95:81:31:fe:9f:00:66:46:53:05:01:00:11:71:df:00:00:03:90:00:80\n",
				71))
			exit(EXIT_FAILURE);
#endif
		DPRINT("RESET, sending ATR, protocol reset to T0\n");
		pps = 0;
	}
}

uint16_t card_io_rx(uint8_t * data, uint16_t len)
{
	ssize_t l;
	uint16_t xlen = len;
	char *line = NULL;
	char *endptr;
	long val;
	char b[65536];
	uint16_t count = 0;

 reread:
	l = read(data_socket, b, sizeof(b));
	if (l == -1)
		exit(0);
	line = b;
	if (l == 4) {
		if (0 == strncmp("> D", line, 3)) {
			DPRINT("Power DOWN\n");
			goto reread;
		}
		if (0 == strncmp("> P", line, 3)) {
			DPRINT("Power UP\n");
			raise(SIGUSR1);
			// wait for signal process
			for (;;) ;
		}
		if (0 == strncmp("> R", line, 3)) {
			DPRINT("RESET\n");
			raise(SIGUSR1);
			// wait for signal process
			for (;;) ;
		}
		if (0 == strncmp("> 0", line, 3)) {
			// TODO PTS allowed only after ATR
			DPRINT("New protocol T0\n");
			data[0] = 0xff;
			data[1] = 0;
			data[2] = 0xff;
			pps = 1;
			return 3;
		}
		if (0 == strncmp("> 1", line, 3)) {
			// TODO PTS allowed only after ATR
			DPRINT("New protocol T1\n");
			data[0] = 0xff;
			data[1] = 1;
			data[2] = 0xfe;
			pps = 1;
			return 3;
		}
	}

	if (l >= 5)
		if (0 == strncmp("reset", line, 5)
		    || 0 == strncmp("RESET", line, 5)) {
			DPRINT("received reset from reader\n");
			fflush(stdin);
			raise(SIGUSR1);
			// wait for signal process
			for (;;) ;
		}
	endptr = line + 1;
	line[l] = 0;
	for (; *endptr && xlen; xlen--) {
		val = strtol(endptr, &endptr, 16);
		val &= 0xff;
		data[count++] = (uint8_t) val;
		while (isspace(*endptr) && *endptr)
			endptr++;
	}
	return count;
}

// for len = 0 transmit 65536 bytes
void card_io_tx(uint8_t * data, uint16_t len)
{
	char b[65536 * 4];
	int count = 2;

	b[0] = '<';
	b[1] = ' ';
// check PPS
	if (pps) {
		pps = 0;
		count += sprintf(b + 2, "%d\n", data[1]);
	} else {
		do {
			count += sprintf(b + count, "%02x ", *data++);
		}
		while (--len);
		count += sprintf(b + count, "\n");
	}
	if (-1 == write(data_socket, b, count))
		exit(1);
	return;
}

void card_io_start_null(void)
{
//  printf ("card_io_start_null\n");

}

void card_io_stop_null(void)
{
//  printf ("card_io_stop_null\n");
}
