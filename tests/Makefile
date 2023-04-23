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
CFLAGS = -DHAVE_CONFIG_H
CFLAGS += -I. -I.. -I../src
CFLAGS += -g -O2 -fvisibility=hidden -fno-delete-null-pointer-checks -Wall -Wcast-align -Wshadow -Wstrict-prototypes -Wformat -Wno-format-y2k -Wformat-security -W -Wextra -Wbad-function-cast -Wwrite-strings -Wdeclaration-after-statement -Wno-missing-field-initializers -Wno-sign-compare -Wpointer-arith
LDLIBS = -lgcrypt -lgpg-error -Wl,-rpath=../src/.libs

BASICS = \
	version t-secmem mpitests t-sexp t-convert \
	t-mpi-bit t-mpi-point t-lock \
	prime basic keygen pubkey hmac hashtest t-kdf keygrip \
	aeswrap random

RSA = pkcs1v2 t-rsa-pss t-rsa-15 t-rsa-testparm

DSA = fips186-dsa dsa-rfc6979 t-dsa

ECC = curves t-ecdsa t-ed25519 t-cv25519 t-x448 t-ed448

BENCHMARK = benchmark bench-slope

NOINST = testdrv fipsdrv rsacvt genhashdata gchash

OTHERS = fipsrngdrv pkbench testapi


basics:
	for f in $(BASICS); do \
		$(CC) $(CFLAGS) $$f.c -o $$f $(LDLIBS) || exit 1; done

basic: basic.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

hmac: hmac.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

hashtest: hashtest.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

aeswrap: aeswrap.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

#### rsa ####

rsa:
	for f in $(RSA); do \
		$(CC) $(CFLAGS) $$f.c -o $$f $(LDLIBS) || exit 1; done

dsa:
	for f in $(DSA); do \
		$(CC) $(CFLAGS) $$f.c -o $$f $(LDLIBS) || exit 1; done

ecc:
	for f in $(ECC); do \
		$(CC) $(CFLAGS) $$f.c -o $$f $(LDLIBS) || exit 1; done

#### benchmark ####

benchmark: benchmark.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

bench-slope: bench-slope.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

noinst:
	for f in $(NOINST); do \
		$(CC) $(CFLAGS) $$f.c -o $$f $(LDLIBS) || exit 1; done

others:
	for f in $(OTHERS); do \
		$(CC) $(CFLAGS) $$f.c -o $$f $(LDLIBS) || exit 1; done

clean-basics:
	for f in $(BASICS); do rm -f $$f; done

clean-rsa:
	for f in $(RSA); do rm $$f; done

clean-dsa:
	for f in $(DSA); do rm -f $$f; done

clean-ecc:
	for f in $(ECC); do rm -f $$f; done

clean-benchmark:
	for f in $(BENCHMARK); do rm -f $$f; done

clean-noinst:
	for f in $(NOINST); do rm -f $$f; done

clean-others:
	for f in $(OTHERS); do rm -f $$f; done
