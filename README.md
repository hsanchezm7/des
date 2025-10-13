# des

Lightweight C implementation of the Data Encryption Standard (DES).

This repository contains an educational, single-file implementation of the
DES block cipher (64-bit block, 56-bit key schedule) intended for
experimentation and learning.

## Features

- Full DES algorithm (initial/final permutations, key schedule, S-boxes,
  Feistel rounds)
- Small, portable C implementation
- Simple command-line interface for encrypting/decrypting single 64-bit blocks

## Requirements

- A C compiler (gcc/clang)
- POSIX-compatible shell

## Build

This repository includes a `Makefile` that builds the project and places the
binary under `bin/` by default. To compile, just run:

```sh
make
```

After a successful `make`, the runnable is `bin/des` and can be used with the
CLI described next.

Alternatively, you can compile directly with gcc:

```sh
gcc -Wall -Wextra -O3 -o des src/des.c
```

You can also run the project's default smoke test (invokes `bin/des -e` with
default MESSAGE/KEY values set in the Makefile)

```sh
make test
```

## Usage

The program accepts a 64-bit key and a 64-bit message in hexadecimal. Key
parity bits are not enforced by this simple implementation.

Basic options:

- `-e` : encrypt
- `-d` : decrypt
- `-k KEY_HEX` : 64-bit key in hex (example: `0123456789ABCDEF`)
- `-m MESSAGE` : 64-bit message/block in hex

Example (encrypt):

```sh
./des -e -k 0123456789ABCDEF -m 0123456789ABCDEF
```

Example (decrypt):

```sh
./des -d -k 0123456789ABCDEF -m <CIPHERTEXT_HEX>
```

For more usage information, please run:

```sh
./des -h
```

Note: The program prints the input and resulting output in hex to stderr.

## Contributing

I plan to extend the functionality by implementing CBC mode, file I/O and 
larger message chunks, so PRs and issues are welcome.

## License

This project is released under the MIT License. See the `LICENSE` file or
header comments in `src/des.c` for details.

## Acknowledgments

- NIST FIPS 46-3 — Official DES specification and standard:
    https://csrc.nist.gov/pubs/fips/46-3/final
  
- DES notes and worked examples (TU Berlin) — helpful educational material:
    https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm

These references were used as background and verification material while
developing this implementation.


