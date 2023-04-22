# libgcrypt-standalone

Libgcrypt-standalone - The standalone compiled version of Libgcrypt

## Overview

Libgcrypt-standalone is the standalone compiled version of  Libgcrypt: the files
in `tests` will be compiled with the  installed shared library
`/usr/lib/libgcrypt.so` on your system instead of the one compiled from the
cloned Libgcrypt itself.

## How to get this repo from libgcrypt

Before using this repo you should guarantee that `libgcrypt` and `libgpg-error`
are installed on your system.

First, clone the libgcrypt project and copy `compat/`, `src/`, `tests/` to an
empty folder, e.g. `libgcrypt-standalone`:

```sh
git clone git://git.gnupg.org/libgcrypt.git && cd libgcrypt
cp -r compat/ src/ tests/ ../libgcrypt-standalone/
```

Then modify the version (check your Libgcrypt version via `pacman -Qi libgcrypt`
or any other commands on your distribution):

```sh
vim configure.ac  # modify the version number in line 32-34
rm -rf .git       # avoid the "beta" version mismatch
```

Third, configure, to yield `config.h`

```sh
./autogen.sh
./configure --enable-maintainer-mode
```

Finally, copy `config.h` to `libgcrypt-standalone` and build:

```sh
cp config.h ../libgcrypt-standalone/
cp src/gcrypt.h ../libgcrypt-standalone/src/
cd ../libgcrypt-standalone/tests/
make basics
make rsa
make dsa
make ecc
make benchmark
make noinst
make others # potentially fail
cd ../src/
make dumpsexp
make hmac256
make mpicalc
```
