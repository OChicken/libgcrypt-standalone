# Copyright (C) 2001, 2002, 2003, 2005 Free Software Foundation, Inc.
#
# This file is part of Libgcrypt.
#
# Libgcrypt is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Libgcrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

# Note: Please keep these tests in sync with those in testdrv.c.
# We will eventually switch over to the the new driver but as of now
# the driver is only used for cross-compiling.

CC = gcc
CFLAGS = -DHAVE_CONFIG_H -DSTANDALONE
CFLAGS += -I. -I.. -I../src
CFLAGS += -g -O2 -fvisibility=hidden -fno-delete-null-pointer-checks -Wall -Wcast-align -Wshadow -Wstrict-prototypes -Wformat -Wno-format-y2k -Wformat-security -W -Wextra -Wbad-function-cast -Wwrite-strings -Wdeclaration-after-statement -Wno-missing-field-initializers -Wno-sign-compare -Wpointer-arith
LDLIBS = -lgcrypt -lgpg-error

dumpsexp: dumpsexp.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

hmac256: hmac256.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

mpicalc: mpicalc.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm dumpsexp hmac256 mpicalc
