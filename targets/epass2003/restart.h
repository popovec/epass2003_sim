/*
    restart.h

    In March 2023, this file was derived from the OsEID project.
    https:/oseid.sourceforge.io
    https://github.com/popovec/oseid

    This is part of epass2003 simulator.

    Copyright (C) 2015-2012 Peter Popovec, popovec.peter@gmail.com

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

    handler - restart of OsEID main

*/
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>

sigjmp_buf JumpBuffer;
void INThandler(int);

void INThandler(int sig)
{
	signal(sig, INThandler);
	siglongjmp(JumpBuffer, 1);
}
