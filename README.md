# SHA3-256 and Keccak implementation

**Author:**  
- Thuy Vi Emilie NGUYEN
  
## Overview

This project provides a command-line tool to compute SHA3-256 hashes for files. It is implemented in C++ and follows the SHA3 standard (FIPS 202) specification closely.

## Features

- Computes SHA3-256 hash for input files somehow efficiently.
- Supports large files without excessive memory usage, thanks to incremental processing.
- Outputs hashes in a standard hexadecimal format.
- Optional timing feature: run `./sha3 -t <file>` to display the computation time.
- A test suite that compares the computed hashes against `openssl sha3-256` for verification.

## Usage

1. **Build the program:**
```sh
make
```
2. **Run the program:**
```sh
./sha3 <file>
```
This print the SHA3-256 hash of the given file.

To measure computation time:
```sh
./sha3 -t <file>
```
This prints both the hash and the time taken.

3. **Run tests:**
```sh
make test
```
This executes run_tests.sh, which compares the hashes produced by ./sha3 against openssl sha3-256 for all test files in test/. We have added visual colors for greater satisfaction. :) 

4. **Clean up:**
```sh
make clean
```

## Implementation Details

We initially started implementing the algorithm in C, but decided to switch to C++ because we are more comfortable and efficient with it. We found it easier to write cleaner, modular code, and still achieve a good computational performance.

**Memory management:**  
We process files in small chunks (4KB), ensuring good memory efficiency and fast execution times.

**Optimizations considered:**
- We avoided unnecessary copying of data by updating the state incrementally.
- The code uses bitwise operations, inline functions, and does not rely on large temporary data structures.
- Endianness conversions and Keccak permutation steps were carefully handled to ensure correctness and portability.

**Additional notes:**
- The final hash matches the reference results from openssl sha3-256.
- The build and test scripts are simple and should work on Unix-like systems that have a compatible C++ compiler and OpenSSL installed.
