### LibreSSL with a Zig build system

This is a somewhat hacky port of the LibreSSL build system to Zig. It builds LibreSSL exclusively as static libraries. It does not (currently) build the LibreSSL command-line executables, like `openssl`.

Notes:

1. In order for this to work, `.\update.sh` must have first been run to bring in the LibreSSL OpenBSD sources. (Or, if you trust me, you may use the `zig-3.8.1` branch which has the upstream sources committed to the repository, for ease of use with the Zig package manager).

2. I don't know if this causes LibreSSL to be compiled in a way that Compromises Its Cryptographic Integrity. Hopefully it is not even possible to do such a thing in the first place. But I am not an expert, and I ain't looking to port the tests.

3. This does not (currently) compile the assembly routines, only the C versions, which may cause reduced performance on some platforms.

4. Only the "big 3" platforms are supported (namely: macOS, Linux, and Windows), and they may be poorly supported, at that. I can cross compile to them from my computer but I have not tried natively compiling on all platforms.

5. Why LibreSSL? It has a CMake-based build system rather than the insane hand-rolled perl mess that OpenSSL does, so it was very straightforward to follow the build process for the purposes of porting it. In theory, its OpenSSL compatibility layer makes it possible to use with a variety of other programs that want to link OpenSSL.

