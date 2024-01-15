const std = @import("std");
const builtin = @import("builtin");

const LibreSslBuildOptions = struct {
    libcrypto_name: []const u8 = "crypto",
    libssl_name: []const u8 = "ssl",
    libtls_name: []const u8 = "tls",
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,
};

const LibreSslLibs = struct {
    libcrypto: *std.Build.Step.Compile,
    libssl: *std.Build.Step.Compile,
    libtls: *std.Build.Step.Compile,

    pub fn linkLibC(self: LibreSslLibs) void {
        self.libcrypto.linkLibC();
        self.libssl.linkLibC();
        self.libtls.linkLibC();
    }

    pub fn linkSystemLibrary(self: LibreSslLibs, library: []const u8) void {
        self.libcrypto.linkSystemLibrary(library);
        self.libssl.linkSystemLibrary(library);
        self.libtls.linkSystemLibrary(library);
    }

    pub fn defineCMacro(self: LibreSslLibs, name: []const u8, value: ?[]const u8) void {
        self.libcrypto.defineCMacro(name, value);
        self.libssl.defineCMacro(name, value);
        self.libtls.defineCMacro(name, value);
    }

    pub fn installArtifact(self: LibreSslLibs, b: *std.Build) void {
        b.installArtifact(self.libcrypto);
        b.installArtifact(self.libssl);
        b.installArtifact(self.libtls);
    }

    pub fn header_search(
        self: LibreSslLibs,
        b: *std.Build,
        base: []const u8,
        skiplist: []const SkipSpec,
    ) !void {
        const dir = try b.build_root.handle.openIterableDir(base, .{});
        var walker = try dir.walk(b.allocator);
        defer walker.deinit();

        walker: while (try walker.next()) |child| {
            for (skiplist) |entry| {
                switch (entry) {
                    .starts_with => |name| if (std.mem.startsWith(u8, child.path, name)) continue :walker,
                    .ends_with => |name| if (std.mem.endsWith(u8, child.path, name)) continue :walker,
                }
            }

            if (std.mem.endsWith(u8, child.basename, ".h")) {
                const full = try std.mem.concat(b.allocator, u8, &.{ base, child.path });
                defer b.allocator.free(full);

                self.libcrypto.installHeader(full, child.path);
                self.libssl.installHeader(full, child.path);
                self.libtls.installHeader(full, child.path);
            }
        }
    }
};

pub fn libresslBuild(
    b: *std.Build,
    options: LibreSslBuildOptions,
) !LibreSslLibs {
    const libressl_libs: LibreSslLibs = .{
        .libcrypto = b.addStaticLibrary(.{
            .name = options.libcrypto_name,
            .target = options.target,
            .optimize = options.optimize,
        }),

        .libssl = b.addStaticLibrary(.{
            .name = options.libssl_name,
            .target = options.target,
            .optimize = options.optimize,
        }),

        .libtls = b.addStaticLibrary(.{
            .name = options.libtls_name,
            .target = options.target,
            .optimize = options.optimize,
        }),
    };

    libressl_libs.linkLibC();

    const tinfo = libressl_libs.libcrypto.target_info.target;

    const common_cflags = [_][]const u8{
        "-fno-sanitize=undefined",
        "-Wno-pointer-sign",
    };

    const cflags: []const []const u8 = switch (tinfo.os.tag) {
        .macos => &(common_cflags ++ [_][]const u8{"-fno-common"}),
        else => &common_cflags,
    };

    libressl_libs.libcrypto.addCSourceFiles(&libcrypto_sources, cflags);
    libressl_libs.libcrypto.addCSourceFiles(&libcrypto_nonasm, cflags);
    libressl_libs.libcrypto.addCSourceFiles(&libcrypto_nonasm_or_armv4, cflags);

    libressl_libs.libssl.addCSourceFiles(&libssl_sources, cflags);

    libressl_libs.libtls.addCSourceFiles(&libtls_sources, cflags);

    libressl_libs.defineCMacro("LIBRESSL_INTERNAL", null);
    libressl_libs.defineCMacro("OPENSSL_NO_HW_PADLOCK", null);
    libressl_libs.defineCMacro("__BEGIN_HIDDEN_DECLS", "");
    libressl_libs.defineCMacro("__END_HIDDEN_DECLS", "");
    libressl_libs.defineCMacro("LIBRESSL_CRYPTO_INTERNAL", null);
    libressl_libs.defineCMacro("OPENSSL_NO_ASM", null);

    switch (tinfo.os.tag) {
        .macos => {
            libressl_libs.libcrypto.addCSourceFiles(&libcrypto_unix_sources, cflags);
            libressl_libs.libcrypto.addCSourceFiles(&libcrypto_macos_compat, cflags);

            libressl_libs.defineCMacro("HAVE_CLOCK_GETTIME", null);
            libressl_libs.defineCMacro("HAVE_ASPRINTF", null);
            libressl_libs.defineCMacro("HAVE_STRCASECMP", null);
            libressl_libs.defineCMacro("HAVE_STRLCAT", null);
            libressl_libs.defineCMacro("HAVE_STRLCPY", null);
            libressl_libs.defineCMacro("HAVE_STRNDUP", null);
            libressl_libs.defineCMacro("HAVE_STRNLEN", null);
            libressl_libs.defineCMacro("HAVE_STRSEP", null);
            libressl_libs.defineCMacro("HAVE_STRTONUM", null);
            libressl_libs.defineCMacro("HAVE_TIMEGM", null);
            libressl_libs.defineCMacro("HAVE_ARC4RANDOM_BUF", null);
            libressl_libs.defineCMacro("HAVE_ARC4RANDOM_UNIFORM", null);
            libressl_libs.defineCMacro("HAVE_GETENTROPY", null);
            libressl_libs.defineCMacro("HAVE_GETPAGESIZE", null);
            libressl_libs.defineCMacro("HAVE_GETPROGNAME", null);
            libressl_libs.defineCMacro("HAVE_MEMMEM", null);
            libressl_libs.defineCMacro("HAVE_MACHINE_ENDIAN_H", null);
            libressl_libs.defineCMacro("HAVE_ERR_H", null);
            libressl_libs.defineCMacro("HAVE_NETINET_IP_H", null);
        },
        .linux => {
            libressl_libs.libcrypto.addCSourceFiles(&libcrypto_unix_sources, cflags);
            libressl_libs.libcrypto.addCSourceFiles(&libcrypto_linux_compat, cflags);

            libressl_libs.defineCMacro("_DEFAULT_SOURCE", null);
            libressl_libs.defineCMacro("_BSD_SOURCE", null);
            libressl_libs.defineCMacro("_POSIX_SOURCE", null);
            libressl_libs.defineCMacro("_GNU_SOURCE", null);

            libressl_libs.defineCMacro("HAVE_ASPRINTF", null);

            libressl_libs.defineCMacro("HAVE_STRCASECMP", null);

            libressl_libs.defineCMacro("HAVE_STRNDUP", null);
            libressl_libs.defineCMacro("HAVE_STRNLEN", null);
            libressl_libs.defineCMacro("HAVE_STRSEP", null);
            libressl_libs.defineCMacro("HAVE_TIMEGM", null);

            libressl_libs.defineCMacro("HAVE_EXPLICIT_BZERO", null);
            libressl_libs.defineCMacro("HAVE_GETAUXVAL", null);
            libressl_libs.defineCMacro("HAVE_GETPAGESIZE", null);

            libressl_libs.defineCMacro("HAVE_SYSLOG", null);
            libressl_libs.defineCMacro("HAVE_TIMESPECSUB", null);
            libressl_libs.defineCMacro("HAVE_MEMMEM", null);
            libressl_libs.defineCMacro("HAVE_ENDIAN_H", null);
            libressl_libs.defineCMacro("HAVE_ERR_H", null);
            libressl_libs.defineCMacro("HAVE_NETINET_IP_H", null);

            if (tinfo.abi.isGnu()) {
                libressl_libs.libcrypto.addCSourceFiles(&libcrypto_linux_glibc_compat, cflags);
            } else if (tinfo.abi.isMusl()) {
                libressl_libs.libcrypto.addCSourceFiles(&libcrypto_linux_musl_compat, cflags);

                libressl_libs.defineCMacro("HAVE_STRLCAT", null);
                libressl_libs.defineCMacro("HAVE_STRLCPY", null);
                libressl_libs.defineCMacro("HAVE_GETENTROPY", null);
            } else @panic("weird ABI, dude");

            libressl_libs.linkSystemLibrary("pthread");
        },
        .windows => {
            libressl_libs.libcrypto.addCSourceFiles(&libcrypto_windows_sources, cflags);
            libressl_libs.libcrypto.addCSourceFiles(&libcrypto_windows_compat, cflags);
            libressl_libs.libtls.addCSourceFiles(&libtls_windows_sources, cflags);

            if (tinfo.abi != .msvc) {
                libressl_libs.defineCMacro("_GNU_SOURCE", null);
                libressl_libs.defineCMacro("_POSIX", null);
                libressl_libs.defineCMacro("_POSIX_SOURCE", null);
                libressl_libs.defineCMacro("__USE_MINGW_ANSI_STDIO", null);
            }

            libressl_libs.defineCMacro("_CRT_SECURE_NO_WARNINGS", null);
            libressl_libs.defineCMacro("_CRT_DEPRECATED_NO_WARNINGS", null);
            libressl_libs.defineCMacro("_REENTRANT", null);
            libressl_libs.defineCMacro("_POSIX_THREAD_SAFE_FUNCTIONS", null);
            libressl_libs.defineCMacro("CPPFLAGS", null);
            libressl_libs.defineCMacro("NO_SYSLOG", null);
            libressl_libs.defineCMacro("NO_CRYPT", null);
            libressl_libs.defineCMacro("WIN32_LEAN_AND_MEAN", null);
            libressl_libs.defineCMacro("_WIN32_WINNT", "0x0600");

            libressl_libs.defineCMacro("HAVE_ASPRINTF", null);
            libressl_libs.defineCMacro("HAVE_STRCASECMP", null);
            libressl_libs.defineCMacro("HAVE_STRNLEN", null);
            libressl_libs.defineCMacro("HAVE_GETAUXVAL", null);

            libressl_libs.defineCMacro("HAVE_TIMESPECSUB", null);
            libressl_libs.defineCMacro("HAVE_MEMMEM", null);
            libressl_libs.defineCMacro("HAVE_MACHINE_ENDIAN_H", null);
            libressl_libs.defineCMacro("HAVE_ERR_H", null);
            libressl_libs.defineCMacro("HAVE_NETINET_IP_H", null);

            libressl_libs.linkSystemLibrary("ws2_32");
            libressl_libs.linkSystemLibrary("bcrypt");
        },

        else => @panic("unsupported target OS"),
    }

    const conf_header = switch (tinfo.cpu.arch) {
        .aarch64, .aarch64_be, .aarch64_32 => source_header_prefix ++ "arch/aarch64/opensslconf.h",
        .x86 => source_header_prefix ++ "arch/i386/opensslconf.h",
        .riscv64 => source_header_prefix ++ "arch/riscv64/opensslconf.h",
        .x86_64 => source_header_prefix ++ "arch/amd64/opensslconf.h",

        else => @panic("unsupported target CPU arch"),
    };

    libressl_libs.libcrypto.installHeader(conf_header, "openssl/opensslconf.h");
    libressl_libs.libssl.installHeader(conf_header, "openssl/opensslconf.h");
    libressl_libs.libtls.installHeader(conf_header, "openssl/opensslconf.h");

    try libressl_libs.header_search(
        b,
        source_header_prefix,
        &.{
            .{ .starts_with = "compat" },
            .{ .starts_with = "arch" },
            .{ .ends_with = "pqueue.h" },
        },
    );

    for (libcrypto_include_paths) |path| {
        libressl_libs.libcrypto.addIncludePath(.{ .path = path });
    }

    for (libssl_include_paths) |path| {
        libressl_libs.libssl.addIncludePath(.{ .path = path });
    }

    for (libtls_include_paths) |path| {
        libressl_libs.libtls.addIncludePath(.{ .path = path });
    }

    switch (tinfo.cpu.arch) {
        .aarch64,
        .aarch64_be,
        .aarch64_32,
        => libressl_libs.libcrypto.addIncludePath(
            .{ .path = libcrypto_src_prefix ++ "bn/arch/aarch64" },
        ),
        .x86 => libressl_libs.libcrypto.addIncludePath(
            .{ .path = libcrypto_src_prefix ++ "bn/arch/i386" },
        ),
        .riscv64 => libressl_libs.libcrypto.addIncludePath(
            .{ .path = libcrypto_src_prefix ++ "bn/arch/riscv64" },
        ),
        .x86_64 => libressl_libs.libcrypto.addIncludePath(
            .{ .path = libcrypto_src_prefix ++ "bn/arch/amd64" },
        ),

        else => @panic("unsupported target CPU arch"),
    }

    // add the header install path to the include path so that compilation will pick
    // up "openssl/opensslconf.h". This is added last to avoid interfering with the
    // somewhat messy include handling that libressl does.
    libressl_libs.libcrypto.addIncludePath(.{ .path = b.getInstallPath(.header, "") });
    libressl_libs.libssl.addIncludePath(.{ .path = b.getInstallPath(.header, "") });
    libressl_libs.libtls.addIncludePath(.{ .path = b.getInstallPath(.header, "") });

    libressl_libs.libssl.linkLibrary(libressl_libs.libcrypto);

    // cmake builds libtls with libcrypto and libssl symbols jammed into it. However,
    // these commands do not result in the same outcome. We could add those sources to
    // the libtls target, but I'd rather not. However, this should result in the
    // desired outcome when using an external zig build system.
    libressl_libs.libtls.linkLibrary(libressl_libs.libcrypto);
    libressl_libs.libtls.linkLibrary(libressl_libs.libssl);

    libressl_libs.installArtifact(b);

    return libressl_libs;
}

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = try libresslBuild(b, .{ .target = target, .optimize = optimize });
}

const SkipSpec = union(enum) {
    starts_with: []const u8,
    ends_with: []const u8,
};

const base_src_prefix = "./";
const libcrypto_src_prefix = base_src_prefix ++ "crypto/";
const source_header_prefix = base_src_prefix ++ "include/";
const libssl_src_prefix = base_src_prefix ++ "ssl/";
const libtls_src_prefix = base_src_prefix ++ "tls/";

// only used on nonasm builds
const libcrypto_nonasm = [_][]const u8{
    libcrypto_src_prefix ++ "aes/aes_core.c",
};

const libcrypto_include_paths = [_][]const u8{
    libcrypto_src_prefix,
    libcrypto_src_prefix ++ "asn1",
    libcrypto_src_prefix ++ "bio",
    libcrypto_src_prefix ++ "bn",
    libcrypto_src_prefix ++ "bytestring",
    libcrypto_src_prefix ++ "dh",
    libcrypto_src_prefix ++ "dsa",
    libcrypto_src_prefix ++ "curve25519",
    libcrypto_src_prefix ++ "ec",
    libcrypto_src_prefix ++ "ecdh",
    libcrypto_src_prefix ++ "ecdsa",
    libcrypto_src_prefix ++ "evp",
    libcrypto_src_prefix ++ "hidden",
    libcrypto_src_prefix ++ "hmac",
    libcrypto_src_prefix ++ "modes",
    libcrypto_src_prefix ++ "ocsp",
    libcrypto_src_prefix ++ "pkcs12",
    libcrypto_src_prefix ++ "rsa",
    libcrypto_src_prefix ++ "sha",
    libcrypto_src_prefix ++ "x509",

    // these are order-dependent and they have to go after the "hidden" directory
    // because the "openssl" include directory is masked inside the "hidden" directory
    // in the source tree. cool.
    source_header_prefix ++ "compat",
    source_header_prefix,
};

// these are used on armv4 with asm, or a nonasm build
const libcrypto_nonasm_or_armv4 = [_][]const u8{
    libcrypto_src_prefix ++ "aes/aes_cbc.c",
    libcrypto_src_prefix ++ "camellia/camellia.c",
    libcrypto_src_prefix ++ "camellia/cmll_cbc.c",
    libcrypto_src_prefix ++ "rc4/rc4_enc.c",
    libcrypto_src_prefix ++ "rc4/rc4_skey.c",
    libcrypto_src_prefix ++ "whrlpool/wp_block.c",
};

const libcrypto_unix_sources = [_][]const u8{
    libcrypto_src_prefix ++ "crypto_lock.c",
    libcrypto_src_prefix ++ "bio/b_posix.c",
    libcrypto_src_prefix ++ "bio/bss_log.c",
    libcrypto_src_prefix ++ "ui/ui_openssl.c",
};

const libcrypto_windows_sources = [_][]const u8{
    libcrypto_src_prefix ++ "compat/crypto_lock_win.c",
    libcrypto_src_prefix ++ "bio/b_win.c",
    libcrypto_src_prefix ++ "ui/ui_openssl_win.c",
    libcrypto_src_prefix ++ "compat/posix_win.c",
};

// TODO: trial and error these?

const libcrypto_macos_compat = [_][]const u8{
    libcrypto_src_prefix ++ "compat/freezero.c",
    libcrypto_src_prefix ++ "compat/reallocarray.c",
    libcrypto_src_prefix ++ "compat/recallocarray.c",

    libcrypto_src_prefix ++ "compat/syslog_r.c",
    libcrypto_src_prefix ++ "compat/explicit_bzero.c",
    libcrypto_src_prefix ++ "compat/timingsafe_bcmp.c",
    libcrypto_src_prefix ++ "compat/timingsafe_memcmp.c",
};

const libcrypto_linux_compat = [_][]const u8{
    libcrypto_src_prefix ++ "compat/freezero.c",
    libcrypto_src_prefix ++ "compat/getprogname_linux.c",

    libcrypto_src_prefix ++ "compat/reallocarray.c",
    libcrypto_src_prefix ++ "compat/recallocarray.c",

    libcrypto_src_prefix ++ "compat/strtonum.c",
    libcrypto_src_prefix ++ "compat/syslog_r.c",

    libcrypto_src_prefix ++ "compat/arc4random.c",
    libcrypto_src_prefix ++ "compat/arc4random_uniform.c",

    libcrypto_src_prefix ++ "compat/explicit_bzero.c",
    libcrypto_src_prefix ++ "compat/timingsafe_bcmp.c",
    libcrypto_src_prefix ++ "compat/timingsafe_memcmp.c",
};

const libcrypto_linux_musl_compat = [_][]const u8{};

const libcrypto_linux_glibc_compat = [_][]const u8{
    libcrypto_src_prefix ++ "compat/strlcat.c",
    libcrypto_src_prefix ++ "compat/strlcpy.c",

    libcrypto_src_prefix ++ "compat/getentropy_linux.c",
};

const libcrypto_windows_compat = [_][]const u8{
    libcrypto_src_prefix ++ "compat/freezero.c",
    libcrypto_src_prefix ++ "compat/getprogname_windows.c",
    libcrypto_src_prefix ++ "compat/getpagesize.c",

    libcrypto_src_prefix ++ "compat/reallocarray.c",
    libcrypto_src_prefix ++ "compat/recallocarray.c",

    libcrypto_src_prefix ++ "compat/strlcat.c",
    libcrypto_src_prefix ++ "compat/strlcpy.c",
    libcrypto_src_prefix ++ "compat/strndup.c",
    libcrypto_src_prefix ++ "compat/strsep.c",
    libcrypto_src_prefix ++ "compat/strtonum.c",

    libcrypto_src_prefix ++ "compat/syslog_r.c",
    libcrypto_src_prefix ++ "compat/timegm.c",

    libcrypto_src_prefix ++ "compat/explicit_bzero_win.c",
    libcrypto_src_prefix ++ "compat/getentropy_win.c",

    libcrypto_src_prefix ++ "compat/arc4random.c",
    libcrypto_src_prefix ++ "compat/arc4random_uniform.c",

    libcrypto_src_prefix ++ "compat/timingsafe_bcmp.c",
    libcrypto_src_prefix ++ "compat/timingsafe_memcmp.c",
};

const libcrypto_sources = [_][]const u8{
    libcrypto_src_prefix ++ "cpt_err.c",
    libcrypto_src_prefix ++ "cryptlib.c",
    libcrypto_src_prefix ++ "crypto_init.c",
    libcrypto_src_prefix ++ "cversion.c",
    libcrypto_src_prefix ++ "ex_data.c",
    libcrypto_src_prefix ++ "malloc-wrapper.c",
    libcrypto_src_prefix ++ "mem_clr.c",
    libcrypto_src_prefix ++ "mem_dbg.c",
    libcrypto_src_prefix ++ "o_fips.c",
    libcrypto_src_prefix ++ "o_init.c",
    libcrypto_src_prefix ++ "o_str.c",
    libcrypto_src_prefix ++ "aes/aes_cfb.c",
    libcrypto_src_prefix ++ "aes/aes_ctr.c",
    libcrypto_src_prefix ++ "aes/aes_ecb.c",
    libcrypto_src_prefix ++ "aes/aes_ige.c",
    libcrypto_src_prefix ++ "aes/aes_ofb.c",
    libcrypto_src_prefix ++ "aes/aes_wrap.c",
    libcrypto_src_prefix ++ "asn1/a_bitstr.c",
    libcrypto_src_prefix ++ "asn1/a_enum.c",
    libcrypto_src_prefix ++ "asn1/a_int.c",
    libcrypto_src_prefix ++ "asn1/a_mbstr.c",
    libcrypto_src_prefix ++ "asn1/a_object.c",
    libcrypto_src_prefix ++ "asn1/a_octet.c",
    libcrypto_src_prefix ++ "asn1/a_pkey.c",
    libcrypto_src_prefix ++ "asn1/a_print.c",
    libcrypto_src_prefix ++ "asn1/a_pubkey.c",
    libcrypto_src_prefix ++ "asn1/a_strex.c",
    libcrypto_src_prefix ++ "asn1/a_string.c",
    libcrypto_src_prefix ++ "asn1/a_strnid.c",
    libcrypto_src_prefix ++ "asn1/a_time.c",
    libcrypto_src_prefix ++ "asn1/a_time_posix.c",
    libcrypto_src_prefix ++ "asn1/a_time_tm.c",
    libcrypto_src_prefix ++ "asn1/a_type.c",
    libcrypto_src_prefix ++ "asn1/a_utf8.c",
    libcrypto_src_prefix ++ "asn1/ameth_lib.c",
    libcrypto_src_prefix ++ "asn1/asn1_err.c",
    libcrypto_src_prefix ++ "asn1/asn1_gen.c",
    libcrypto_src_prefix ++ "asn1/asn1_item.c",
    libcrypto_src_prefix ++ "asn1/asn1_lib.c",
    libcrypto_src_prefix ++ "asn1/asn1_old.c",
    libcrypto_src_prefix ++ "asn1/asn1_old_lib.c",
    libcrypto_src_prefix ++ "asn1/asn1_par.c",
    libcrypto_src_prefix ++ "asn1/asn1_types.c",
    libcrypto_src_prefix ++ "asn1/asn_mime.c",
    libcrypto_src_prefix ++ "asn1/asn_moid.c",
    libcrypto_src_prefix ++ "asn1/bio_asn1.c",
    libcrypto_src_prefix ++ "asn1/bio_ndef.c",
    libcrypto_src_prefix ++ "asn1/p5_pbe.c",
    libcrypto_src_prefix ++ "asn1/p5_pbev2.c",
    libcrypto_src_prefix ++ "asn1/p8_pkey.c",
    libcrypto_src_prefix ++ "asn1/t_crl.c",
    libcrypto_src_prefix ++ "asn1/t_req.c",
    libcrypto_src_prefix ++ "asn1/t_spki.c",
    libcrypto_src_prefix ++ "asn1/t_x509.c",
    libcrypto_src_prefix ++ "asn1/t_x509a.c",
    libcrypto_src_prefix ++ "asn1/tasn_dec.c",
    libcrypto_src_prefix ++ "asn1/tasn_enc.c",
    libcrypto_src_prefix ++ "asn1/tasn_fre.c",
    libcrypto_src_prefix ++ "asn1/tasn_new.c",
    libcrypto_src_prefix ++ "asn1/tasn_prn.c",
    libcrypto_src_prefix ++ "asn1/tasn_typ.c",
    libcrypto_src_prefix ++ "asn1/tasn_utl.c",
    libcrypto_src_prefix ++ "asn1/x_algor.c",
    libcrypto_src_prefix ++ "asn1/x_attrib.c",
    libcrypto_src_prefix ++ "asn1/x_bignum.c",
    libcrypto_src_prefix ++ "asn1/x_crl.c",
    libcrypto_src_prefix ++ "asn1/x_exten.c",
    libcrypto_src_prefix ++ "asn1/x_info.c",
    libcrypto_src_prefix ++ "asn1/x_long.c",
    libcrypto_src_prefix ++ "asn1/x_name.c",
    libcrypto_src_prefix ++ "asn1/x_pkey.c",
    libcrypto_src_prefix ++ "asn1/x_pubkey.c",
    libcrypto_src_prefix ++ "asn1/x_req.c",
    libcrypto_src_prefix ++ "asn1/x_sig.c",
    libcrypto_src_prefix ++ "asn1/x_spki.c",
    libcrypto_src_prefix ++ "asn1/x_val.c",
    libcrypto_src_prefix ++ "asn1/x_x509.c",
    libcrypto_src_prefix ++ "asn1/x_x509a.c",
    libcrypto_src_prefix ++ "bf/bf_cfb64.c",
    libcrypto_src_prefix ++ "bf/bf_ecb.c",
    libcrypto_src_prefix ++ "bf/bf_enc.c",
    libcrypto_src_prefix ++ "bf/bf_ofb64.c",
    libcrypto_src_prefix ++ "bf/bf_skey.c",
    libcrypto_src_prefix ++ "bio/b_dump.c",
    libcrypto_src_prefix ++ "bio/b_print.c",
    libcrypto_src_prefix ++ "bio/b_sock.c",
    libcrypto_src_prefix ++ "bio/bf_buff.c",
    libcrypto_src_prefix ++ "bio/bf_nbio.c",
    libcrypto_src_prefix ++ "bio/bf_null.c",
    libcrypto_src_prefix ++ "bio/bio_cb.c",
    libcrypto_src_prefix ++ "bio/bio_err.c",
    libcrypto_src_prefix ++ "bio/bio_lib.c",
    libcrypto_src_prefix ++ "bio/bio_meth.c",
    libcrypto_src_prefix ++ "bio/bss_acpt.c",
    libcrypto_src_prefix ++ "bio/bss_bio.c",
    libcrypto_src_prefix ++ "bio/bss_conn.c",
    libcrypto_src_prefix ++ "bio/bss_dgram.c",
    libcrypto_src_prefix ++ "bio/bss_fd.c",
    libcrypto_src_prefix ++ "bio/bss_file.c",
    libcrypto_src_prefix ++ "bio/bss_mem.c",
    libcrypto_src_prefix ++ "bio/bss_null.c",
    libcrypto_src_prefix ++ "bio/bss_sock.c",
    libcrypto_src_prefix ++ "bn/bn_add.c",
    libcrypto_src_prefix ++ "bn/bn_bpsw.c",
    libcrypto_src_prefix ++ "bn/bn_const.c",
    libcrypto_src_prefix ++ "bn/bn_convert.c",
    libcrypto_src_prefix ++ "bn/bn_ctx.c",
    libcrypto_src_prefix ++ "bn/bn_div.c",
    libcrypto_src_prefix ++ "bn/bn_err.c",
    libcrypto_src_prefix ++ "bn/bn_exp.c",
    libcrypto_src_prefix ++ "bn/bn_gcd.c",
    libcrypto_src_prefix ++ "bn/bn_isqrt.c",
    libcrypto_src_prefix ++ "bn/bn_kron.c",
    libcrypto_src_prefix ++ "bn/bn_lib.c",
    libcrypto_src_prefix ++ "bn/bn_mod.c",
    libcrypto_src_prefix ++ "bn/bn_mod_sqrt.c",
    libcrypto_src_prefix ++ "bn/bn_mont.c",
    libcrypto_src_prefix ++ "bn/bn_mul.c",
    libcrypto_src_prefix ++ "bn/bn_prime.c",
    libcrypto_src_prefix ++ "bn/bn_primitives.c",
    libcrypto_src_prefix ++ "bn/bn_print.c",
    libcrypto_src_prefix ++ "bn/bn_rand.c",
    libcrypto_src_prefix ++ "bn/bn_recp.c",
    libcrypto_src_prefix ++ "bn/bn_shift.c",
    libcrypto_src_prefix ++ "bn/bn_small_primes.c",
    libcrypto_src_prefix ++ "bn/bn_sqr.c",
    libcrypto_src_prefix ++ "bn/bn_word.c",
    libcrypto_src_prefix ++ "buffer/buf_err.c",
    libcrypto_src_prefix ++ "buffer/buffer.c",
    libcrypto_src_prefix ++ "bytestring/bs_ber.c",
    libcrypto_src_prefix ++ "bytestring/bs_cbb.c",
    libcrypto_src_prefix ++ "bytestring/bs_cbs.c",
    libcrypto_src_prefix ++ "camellia/cmll_cfb.c",
    libcrypto_src_prefix ++ "camellia/cmll_ctr.c",
    libcrypto_src_prefix ++ "camellia/cmll_ecb.c",
    libcrypto_src_prefix ++ "camellia/cmll_misc.c",
    libcrypto_src_prefix ++ "camellia/cmll_ofb.c",
    libcrypto_src_prefix ++ "cast/c_cfb64.c",
    libcrypto_src_prefix ++ "cast/c_ecb.c",
    libcrypto_src_prefix ++ "cast/c_enc.c",
    libcrypto_src_prefix ++ "cast/c_ofb64.c",
    libcrypto_src_prefix ++ "cast/c_skey.c",
    libcrypto_src_prefix ++ "chacha/chacha.c",
    libcrypto_src_prefix ++ "cmac/cm_ameth.c",
    libcrypto_src_prefix ++ "cmac/cm_pmeth.c",
    libcrypto_src_prefix ++ "cmac/cmac.c",
    libcrypto_src_prefix ++ "cms/cms_asn1.c",
    libcrypto_src_prefix ++ "cms/cms_att.c",
    libcrypto_src_prefix ++ "cms/cms_dd.c",
    libcrypto_src_prefix ++ "cms/cms_enc.c",
    libcrypto_src_prefix ++ "cms/cms_env.c",
    libcrypto_src_prefix ++ "cms/cms_err.c",
    libcrypto_src_prefix ++ "cms/cms_ess.c",
    libcrypto_src_prefix ++ "cms/cms_io.c",
    libcrypto_src_prefix ++ "cms/cms_kari.c",
    libcrypto_src_prefix ++ "cms/cms_lib.c",
    libcrypto_src_prefix ++ "cms/cms_pwri.c",
    libcrypto_src_prefix ++ "cms/cms_sd.c",
    libcrypto_src_prefix ++ "cms/cms_smime.c",
    libcrypto_src_prefix ++ "conf/conf_api.c",
    libcrypto_src_prefix ++ "conf/conf_def.c",
    libcrypto_src_prefix ++ "conf/conf_err.c",
    libcrypto_src_prefix ++ "conf/conf_lib.c",
    libcrypto_src_prefix ++ "conf/conf_mall.c",
    libcrypto_src_prefix ++ "conf/conf_mod.c",
    libcrypto_src_prefix ++ "conf/conf_sap.c",
    libcrypto_src_prefix ++ "ct/ct_b64.c",
    libcrypto_src_prefix ++ "ct/ct_err.c",
    libcrypto_src_prefix ++ "ct/ct_log.c",
    libcrypto_src_prefix ++ "ct/ct_oct.c",
    libcrypto_src_prefix ++ "ct/ct_policy.c",
    libcrypto_src_prefix ++ "ct/ct_prn.c",
    libcrypto_src_prefix ++ "ct/ct_sct.c",
    libcrypto_src_prefix ++ "ct/ct_sct_ctx.c",
    libcrypto_src_prefix ++ "ct/ct_vfy.c",
    libcrypto_src_prefix ++ "ct/ct_x509v3.c",
    libcrypto_src_prefix ++ "curve25519/curve25519-generic.c",
    libcrypto_src_prefix ++ "curve25519/curve25519.c",
    libcrypto_src_prefix ++ "des/cbc_cksm.c",
    libcrypto_src_prefix ++ "des/cbc_enc.c",
    libcrypto_src_prefix ++ "des/cfb64ede.c",
    libcrypto_src_prefix ++ "des/cfb64enc.c",
    libcrypto_src_prefix ++ "des/cfb_enc.c",
    libcrypto_src_prefix ++ "des/des_enc.c",
    libcrypto_src_prefix ++ "des/ecb3_enc.c",
    libcrypto_src_prefix ++ "des/ecb_enc.c",
    libcrypto_src_prefix ++ "des/ede_cbcm_enc.c",
    libcrypto_src_prefix ++ "des/enc_read.c",
    libcrypto_src_prefix ++ "des/enc_writ.c",
    libcrypto_src_prefix ++ "des/fcrypt.c",
    libcrypto_src_prefix ++ "des/fcrypt_b.c",
    libcrypto_src_prefix ++ "des/ofb64ede.c",
    libcrypto_src_prefix ++ "des/ofb64enc.c",
    libcrypto_src_prefix ++ "des/ofb_enc.c",
    libcrypto_src_prefix ++ "des/pcbc_enc.c",
    libcrypto_src_prefix ++ "des/qud_cksm.c",
    libcrypto_src_prefix ++ "des/rand_key.c",
    libcrypto_src_prefix ++ "des/set_key.c",
    libcrypto_src_prefix ++ "des/str2key.c",
    libcrypto_src_prefix ++ "des/xcbc_enc.c",
    libcrypto_src_prefix ++ "dh/dh_ameth.c",
    libcrypto_src_prefix ++ "dh/dh_asn1.c",
    libcrypto_src_prefix ++ "dh/dh_check.c",
    libcrypto_src_prefix ++ "dh/dh_err.c",
    libcrypto_src_prefix ++ "dh/dh_gen.c",
    libcrypto_src_prefix ++ "dh/dh_key.c",
    libcrypto_src_prefix ++ "dh/dh_lib.c",
    libcrypto_src_prefix ++ "dh/dh_pmeth.c",
    libcrypto_src_prefix ++ "dsa/dsa_ameth.c",
    libcrypto_src_prefix ++ "dsa/dsa_asn1.c",
    libcrypto_src_prefix ++ "dsa/dsa_err.c",
    libcrypto_src_prefix ++ "dsa/dsa_gen.c",
    libcrypto_src_prefix ++ "dsa/dsa_key.c",
    libcrypto_src_prefix ++ "dsa/dsa_lib.c",
    libcrypto_src_prefix ++ "dsa/dsa_meth.c",
    libcrypto_src_prefix ++ "dsa/dsa_ossl.c",
    libcrypto_src_prefix ++ "dsa/dsa_pmeth.c",
    libcrypto_src_prefix ++ "dsa/dsa_prn.c",
    libcrypto_src_prefix ++ "ec/ec_ameth.c",
    libcrypto_src_prefix ++ "ec/ec_asn1.c",
    libcrypto_src_prefix ++ "ec/ec_check.c",
    libcrypto_src_prefix ++ "ec/ec_curve.c",
    libcrypto_src_prefix ++ "ec/ec_cvt.c",
    libcrypto_src_prefix ++ "ec/ec_err.c",
    libcrypto_src_prefix ++ "ec/ec_key.c",
    libcrypto_src_prefix ++ "ec/ec_kmeth.c",
    libcrypto_src_prefix ++ "ec/ec_lib.c",
    libcrypto_src_prefix ++ "ec/ec_mult.c",
    libcrypto_src_prefix ++ "ec/ec_oct.c",
    libcrypto_src_prefix ++ "ec/ec_pmeth.c",
    libcrypto_src_prefix ++ "ec/ec_print.c",
    libcrypto_src_prefix ++ "ec/eck_prn.c",
    libcrypto_src_prefix ++ "ec/ecp_mont.c",
    libcrypto_src_prefix ++ "ec/ecp_oct.c",
    libcrypto_src_prefix ++ "ec/ecp_smpl.c",
    libcrypto_src_prefix ++ "ec/ecx_methods.c",
    libcrypto_src_prefix ++ "ecdh/ecdh.c",
    libcrypto_src_prefix ++ "ecdsa/ecdsa.c",
    libcrypto_src_prefix ++ "engine/engine_stubs.c",
    libcrypto_src_prefix ++ "err/err.c",
    libcrypto_src_prefix ++ "err/err_all.c",
    libcrypto_src_prefix ++ "err/err_prn.c",
    libcrypto_src_prefix ++ "evp/bio_b64.c",
    libcrypto_src_prefix ++ "evp/bio_enc.c",
    libcrypto_src_prefix ++ "evp/bio_md.c",
    libcrypto_src_prefix ++ "evp/c_all.c",
    libcrypto_src_prefix ++ "evp/cipher_method_lib.c",
    libcrypto_src_prefix ++ "evp/digest.c",
    libcrypto_src_prefix ++ "evp/e_aes.c",
    libcrypto_src_prefix ++ "evp/e_aes_cbc_hmac_sha1.c",
    libcrypto_src_prefix ++ "evp/e_bf.c",
    libcrypto_src_prefix ++ "evp/e_camellia.c",
    libcrypto_src_prefix ++ "evp/e_cast.c",
    libcrypto_src_prefix ++ "evp/e_chacha.c",
    libcrypto_src_prefix ++ "evp/e_chacha20poly1305.c",
    libcrypto_src_prefix ++ "evp/e_des.c",
    libcrypto_src_prefix ++ "evp/e_des3.c",
    libcrypto_src_prefix ++ "evp/e_gost2814789.c",
    libcrypto_src_prefix ++ "evp/e_idea.c",
    libcrypto_src_prefix ++ "evp/e_null.c",
    libcrypto_src_prefix ++ "evp/e_rc2.c",
    libcrypto_src_prefix ++ "evp/e_rc4.c",
    libcrypto_src_prefix ++ "evp/e_rc4_hmac_md5.c",
    libcrypto_src_prefix ++ "evp/e_sm4.c",
    libcrypto_src_prefix ++ "evp/e_xcbc_d.c",
    libcrypto_src_prefix ++ "evp/encode.c",
    libcrypto_src_prefix ++ "evp/evp_aead.c",
    libcrypto_src_prefix ++ "evp/evp_enc.c",
    libcrypto_src_prefix ++ "evp/evp_err.c",
    libcrypto_src_prefix ++ "evp/evp_key.c",
    libcrypto_src_prefix ++ "evp/evp_lib.c",
    libcrypto_src_prefix ++ "evp/evp_pbe.c",
    libcrypto_src_prefix ++ "evp/evp_pkey.c",
    libcrypto_src_prefix ++ "evp/m_gost2814789.c",
    libcrypto_src_prefix ++ "evp/m_gostr341194.c",
    libcrypto_src_prefix ++ "evp/m_md4.c",
    libcrypto_src_prefix ++ "evp/m_md5.c",
    libcrypto_src_prefix ++ "evp/m_md5_sha1.c",
    libcrypto_src_prefix ++ "evp/m_null.c",
    libcrypto_src_prefix ++ "evp/m_ripemd.c",
    libcrypto_src_prefix ++ "evp/m_sha1.c",
    libcrypto_src_prefix ++ "evp/m_sha3.c",
    libcrypto_src_prefix ++ "evp/m_sigver.c",
    libcrypto_src_prefix ++ "evp/m_streebog.c",
    libcrypto_src_prefix ++ "evp/m_sm3.c",
    libcrypto_src_prefix ++ "evp/m_wp.c",
    libcrypto_src_prefix ++ "evp/names.c",
    libcrypto_src_prefix ++ "evp/p5_crpt.c",
    libcrypto_src_prefix ++ "evp/p5_crpt2.c",
    libcrypto_src_prefix ++ "evp/p_dec.c",
    libcrypto_src_prefix ++ "evp/p_enc.c",
    libcrypto_src_prefix ++ "evp/p_lib.c",
    libcrypto_src_prefix ++ "evp/p_open.c",
    libcrypto_src_prefix ++ "evp/p_seal.c",
    libcrypto_src_prefix ++ "evp/p_sign.c",
    libcrypto_src_prefix ++ "evp/p_verify.c",
    libcrypto_src_prefix ++ "evp/pmeth_fn.c",
    libcrypto_src_prefix ++ "evp/pmeth_gn.c",
    libcrypto_src_prefix ++ "evp/pmeth_lib.c",
    libcrypto_src_prefix ++ "gost/gost2814789.c",
    libcrypto_src_prefix ++ "gost/gost89_keywrap.c",
    libcrypto_src_prefix ++ "gost/gost89_params.c",
    libcrypto_src_prefix ++ "gost/gost89imit_ameth.c",
    libcrypto_src_prefix ++ "gost/gost89imit_pmeth.c",
    libcrypto_src_prefix ++ "gost/gost_asn1.c",
    libcrypto_src_prefix ++ "gost/gost_err.c",
    libcrypto_src_prefix ++ "gost/gostr341001.c",
    libcrypto_src_prefix ++ "gost/gostr341001_ameth.c",
    libcrypto_src_prefix ++ "gost/gostr341001_key.c",
    libcrypto_src_prefix ++ "gost/gostr341001_params.c",
    libcrypto_src_prefix ++ "gost/gostr341001_pmeth.c",
    libcrypto_src_prefix ++ "gost/gostr341194.c",
    libcrypto_src_prefix ++ "gost/streebog.c",
    libcrypto_src_prefix ++ "hkdf/hkdf.c",
    libcrypto_src_prefix ++ "hmac/hm_ameth.c",
    libcrypto_src_prefix ++ "hmac/hm_pmeth.c",
    libcrypto_src_prefix ++ "hmac/hmac.c",
    libcrypto_src_prefix ++ "idea/i_cbc.c",
    libcrypto_src_prefix ++ "idea/i_cfb64.c",
    libcrypto_src_prefix ++ "idea/i_ecb.c",
    libcrypto_src_prefix ++ "idea/i_ofb64.c",
    libcrypto_src_prefix ++ "idea/i_skey.c",
    libcrypto_src_prefix ++ "kdf/hkdf_evp.c",
    libcrypto_src_prefix ++ "kdf/kdf_err.c",
    libcrypto_src_prefix ++ "lhash/lh_stats.c",
    libcrypto_src_prefix ++ "lhash/lhash.c",
    libcrypto_src_prefix ++ "md4/md4.c",
    libcrypto_src_prefix ++ "md5/md5.c",
    libcrypto_src_prefix ++ "modes/cbc128.c",
    libcrypto_src_prefix ++ "modes/ccm128.c",
    libcrypto_src_prefix ++ "modes/cfb128.c",
    libcrypto_src_prefix ++ "modes/ctr128.c",
    libcrypto_src_prefix ++ "modes/gcm128.c",
    libcrypto_src_prefix ++ "modes/ofb128.c",
    libcrypto_src_prefix ++ "modes/xts128.c",
    libcrypto_src_prefix ++ "objects/o_names.c",
    libcrypto_src_prefix ++ "objects/obj_dat.c",
    libcrypto_src_prefix ++ "objects/obj_err.c",
    libcrypto_src_prefix ++ "objects/obj_lib.c",
    libcrypto_src_prefix ++ "objects/obj_xref.c",
    libcrypto_src_prefix ++ "ocsp/ocsp_asn.c",
    libcrypto_src_prefix ++ "ocsp/ocsp_cl.c",
    libcrypto_src_prefix ++ "ocsp/ocsp_err.c",
    libcrypto_src_prefix ++ "ocsp/ocsp_ext.c",
    libcrypto_src_prefix ++ "ocsp/ocsp_ht.c",
    libcrypto_src_prefix ++ "ocsp/ocsp_lib.c",
    libcrypto_src_prefix ++ "ocsp/ocsp_prn.c",
    libcrypto_src_prefix ++ "ocsp/ocsp_srv.c",
    libcrypto_src_prefix ++ "ocsp/ocsp_vfy.c",
    libcrypto_src_prefix ++ "pem/pem_all.c",
    libcrypto_src_prefix ++ "pem/pem_err.c",
    libcrypto_src_prefix ++ "pem/pem_info.c",
    libcrypto_src_prefix ++ "pem/pem_lib.c",
    libcrypto_src_prefix ++ "pem/pem_oth.c",
    libcrypto_src_prefix ++ "pem/pem_pk8.c",
    libcrypto_src_prefix ++ "pem/pem_pkey.c",
    libcrypto_src_prefix ++ "pem/pem_sign.c",
    libcrypto_src_prefix ++ "pem/pem_x509.c",
    libcrypto_src_prefix ++ "pem/pem_xaux.c",
    libcrypto_src_prefix ++ "pem/pvkfmt.c",
    libcrypto_src_prefix ++ "pkcs12/p12_add.c",
    libcrypto_src_prefix ++ "pkcs12/p12_asn.c",
    libcrypto_src_prefix ++ "pkcs12/p12_attr.c",
    libcrypto_src_prefix ++ "pkcs12/p12_crpt.c",
    libcrypto_src_prefix ++ "pkcs12/p12_crt.c",
    libcrypto_src_prefix ++ "pkcs12/p12_decr.c",
    libcrypto_src_prefix ++ "pkcs12/p12_init.c",
    libcrypto_src_prefix ++ "pkcs12/p12_key.c",
    libcrypto_src_prefix ++ "pkcs12/p12_kiss.c",
    libcrypto_src_prefix ++ "pkcs12/p12_mutl.c",
    libcrypto_src_prefix ++ "pkcs12/p12_npas.c",
    libcrypto_src_prefix ++ "pkcs12/p12_p8d.c",
    libcrypto_src_prefix ++ "pkcs12/p12_p8e.c",
    libcrypto_src_prefix ++ "pkcs12/p12_sbag.c",
    libcrypto_src_prefix ++ "pkcs12/p12_utl.c",
    libcrypto_src_prefix ++ "pkcs12/pk12err.c",
    libcrypto_src_prefix ++ "pkcs7/pk7_asn1.c",
    libcrypto_src_prefix ++ "pkcs7/pk7_attr.c",
    libcrypto_src_prefix ++ "pkcs7/pk7_doit.c",
    libcrypto_src_prefix ++ "pkcs7/pk7_lib.c",
    libcrypto_src_prefix ++ "pkcs7/pk7_mime.c",
    libcrypto_src_prefix ++ "pkcs7/pk7_smime.c",
    libcrypto_src_prefix ++ "pkcs7/pkcs7err.c",
    libcrypto_src_prefix ++ "poly1305/poly1305.c",
    libcrypto_src_prefix ++ "rand/rand_err.c",
    libcrypto_src_prefix ++ "rand/rand_lib.c",
    libcrypto_src_prefix ++ "rand/randfile.c",
    libcrypto_src_prefix ++ "rc2/rc2_cbc.c",
    libcrypto_src_prefix ++ "rc2/rc2_ecb.c",
    libcrypto_src_prefix ++ "rc2/rc2_skey.c",
    libcrypto_src_prefix ++ "rc2/rc2cfb64.c",
    libcrypto_src_prefix ++ "rc2/rc2ofb64.c",
    libcrypto_src_prefix ++ "ripemd/ripemd.c",
    libcrypto_src_prefix ++ "rsa/rsa_ameth.c",
    libcrypto_src_prefix ++ "rsa/rsa_asn1.c",
    libcrypto_src_prefix ++ "rsa/rsa_blinding.c",
    libcrypto_src_prefix ++ "rsa/rsa_chk.c",
    libcrypto_src_prefix ++ "rsa/rsa_eay.c",
    libcrypto_src_prefix ++ "rsa/rsa_err.c",
    libcrypto_src_prefix ++ "rsa/rsa_gen.c",
    libcrypto_src_prefix ++ "rsa/rsa_lib.c",
    libcrypto_src_prefix ++ "rsa/rsa_meth.c",
    libcrypto_src_prefix ++ "rsa/rsa_none.c",
    libcrypto_src_prefix ++ "rsa/rsa_oaep.c",
    libcrypto_src_prefix ++ "rsa/rsa_pk1.c",
    libcrypto_src_prefix ++ "rsa/rsa_pmeth.c",
    libcrypto_src_prefix ++ "rsa/rsa_prn.c",
    libcrypto_src_prefix ++ "rsa/rsa_pss.c",
    libcrypto_src_prefix ++ "rsa/rsa_saos.c",
    libcrypto_src_prefix ++ "rsa/rsa_sign.c",
    libcrypto_src_prefix ++ "rsa/rsa_x931.c",
    libcrypto_src_prefix ++ "sha/sha1.c",
    libcrypto_src_prefix ++ "sha/sha256.c",
    libcrypto_src_prefix ++ "sha/sha3.c",
    libcrypto_src_prefix ++ "sha/sha512.c",
    libcrypto_src_prefix ++ "sm3/sm3.c",
    libcrypto_src_prefix ++ "sm4/sm4.c",
    libcrypto_src_prefix ++ "stack/stack.c",
    libcrypto_src_prefix ++ "ts/ts_asn1.c",
    libcrypto_src_prefix ++ "ts/ts_conf.c",
    libcrypto_src_prefix ++ "ts/ts_err.c",
    libcrypto_src_prefix ++ "ts/ts_lib.c",
    libcrypto_src_prefix ++ "ts/ts_req_print.c",
    libcrypto_src_prefix ++ "ts/ts_req_utils.c",
    libcrypto_src_prefix ++ "ts/ts_rsp_print.c",
    libcrypto_src_prefix ++ "ts/ts_rsp_sign.c",
    libcrypto_src_prefix ++ "ts/ts_rsp_utils.c",
    libcrypto_src_prefix ++ "ts/ts_rsp_verify.c",
    libcrypto_src_prefix ++ "ts/ts_verify_ctx.c",
    libcrypto_src_prefix ++ "txt_db/txt_db.c",
    libcrypto_src_prefix ++ "ui/ui_err.c",
    libcrypto_src_prefix ++ "ui/ui_lib.c",
    libcrypto_src_prefix ++ "ui/ui_null.c",
    libcrypto_src_prefix ++ "ui/ui_util.c",
    libcrypto_src_prefix ++ "whrlpool/wp_dgst.c",
    libcrypto_src_prefix ++ "x509/by_dir.c",
    libcrypto_src_prefix ++ "x509/by_file.c",
    libcrypto_src_prefix ++ "x509/by_mem.c",
    libcrypto_src_prefix ++ "x509/x509_addr.c",
    libcrypto_src_prefix ++ "x509/x509_akey.c",
    libcrypto_src_prefix ++ "x509/x509_akeya.c",
    libcrypto_src_prefix ++ "x509/x509_alt.c",
    libcrypto_src_prefix ++ "x509/x509_asid.c",
    libcrypto_src_prefix ++ "x509/x509_att.c",
    libcrypto_src_prefix ++ "x509/x509_bcons.c",
    libcrypto_src_prefix ++ "x509/x509_bitst.c",
    libcrypto_src_prefix ++ "x509/x509_cmp.c",
    libcrypto_src_prefix ++ "x509/x509_conf.c",
    libcrypto_src_prefix ++ "x509/x509_constraints.c",
    libcrypto_src_prefix ++ "x509/x509_cpols.c",
    libcrypto_src_prefix ++ "x509/x509_crld.c",
    libcrypto_src_prefix ++ "x509/x509_d2.c",
    libcrypto_src_prefix ++ "x509/x509_def.c",
    libcrypto_src_prefix ++ "x509/x509_err.c",
    libcrypto_src_prefix ++ "x509/x509_ext.c",
    libcrypto_src_prefix ++ "x509/x509_extku.c",
    libcrypto_src_prefix ++ "x509/x509_genn.c",
    libcrypto_src_prefix ++ "x509/x509_ia5.c",
    libcrypto_src_prefix ++ "x509/x509_info.c",
    libcrypto_src_prefix ++ "x509/x509_int.c",
    libcrypto_src_prefix ++ "x509/x509_issuer_cache.c",
    libcrypto_src_prefix ++ "x509/x509_lib.c",
    libcrypto_src_prefix ++ "x509/x509_lu.c",
    libcrypto_src_prefix ++ "x509/x509_ncons.c",
    libcrypto_src_prefix ++ "x509/x509_obj.c",
    libcrypto_src_prefix ++ "x509/x509_ocsp.c",
    libcrypto_src_prefix ++ "x509/x509_pcons.c",
    libcrypto_src_prefix ++ "x509/x509_pku.c",
    libcrypto_src_prefix ++ "x509/x509_pmaps.c",
    libcrypto_src_prefix ++ "x509/x509_policy.c",
    libcrypto_src_prefix ++ "x509/x509_prn.c",
    libcrypto_src_prefix ++ "x509/x509_purp.c",
    libcrypto_src_prefix ++ "x509/x509_r2x.c",
    libcrypto_src_prefix ++ "x509/x509_req.c",
    libcrypto_src_prefix ++ "x509/x509_set.c",
    libcrypto_src_prefix ++ "x509/x509_skey.c",
    libcrypto_src_prefix ++ "x509/x509_trs.c",
    libcrypto_src_prefix ++ "x509/x509_txt.c",
    libcrypto_src_prefix ++ "x509/x509_utl.c",
    libcrypto_src_prefix ++ "x509/x509_v3.c",
    libcrypto_src_prefix ++ "x509/x509_verify.c",
    libcrypto_src_prefix ++ "x509/x509_vfy.c",
    libcrypto_src_prefix ++ "x509/x509_vpm.c",
    libcrypto_src_prefix ++ "x509/x509cset.c",
    libcrypto_src_prefix ++ "x509/x509name.c",
    libcrypto_src_prefix ++ "x509/x509rset.c",
    libcrypto_src_prefix ++ "x509/x509spki.c",
    libcrypto_src_prefix ++ "x509/x509type.c",
    libcrypto_src_prefix ++ "x509/x_all.c",
};

const libssl_include_paths = [_][]const u8{
    libssl_src_prefix,
    libssl_src_prefix ++ "hidden",

    libcrypto_src_prefix ++ "bio",

    // these are order-dependent and they have to go after the "hidden" directory
    // because the "openssl" include directory is masked inside the "hidden" directory
    // in the source tree. cool.
    source_header_prefix ++ "compat",
    source_header_prefix,
};

const libssl_sources = [_][]const u8{
    // these are compiled separately by Cmake, with a slightly different include path.
    // It appears they're only linked if shared libraries are being built? I don't get
    // it. I doubt always building them causes a problem, though.
    libssl_src_prefix ++ "bs_ber.c",
    libssl_src_prefix ++ "bs_cbb.c",
    libssl_src_prefix ++ "bs_cbs.c",

    libssl_src_prefix ++ "bio_ssl.c",
    libssl_src_prefix ++ "d1_both.c",
    libssl_src_prefix ++ "d1_lib.c",
    libssl_src_prefix ++ "d1_pkt.c",
    libssl_src_prefix ++ "d1_srtp.c",
    libssl_src_prefix ++ "pqueue.c",
    libssl_src_prefix ++ "s3_cbc.c",
    libssl_src_prefix ++ "s3_lib.c",
    libssl_src_prefix ++ "ssl_algs.c",
    libssl_src_prefix ++ "ssl_asn1.c",
    libssl_src_prefix ++ "ssl_both.c",
    libssl_src_prefix ++ "ssl_cert.c",
    libssl_src_prefix ++ "ssl_ciph.c",
    libssl_src_prefix ++ "ssl_ciphers.c",
    libssl_src_prefix ++ "ssl_clnt.c",
    libssl_src_prefix ++ "ssl_err.c",
    libssl_src_prefix ++ "ssl_init.c",
    libssl_src_prefix ++ "ssl_kex.c",
    libssl_src_prefix ++ "ssl_lib.c",
    libssl_src_prefix ++ "ssl_methods.c",
    libssl_src_prefix ++ "ssl_packet.c",
    libssl_src_prefix ++ "ssl_pkt.c",
    libssl_src_prefix ++ "ssl_rsa.c",
    libssl_src_prefix ++ "ssl_seclevel.c",
    libssl_src_prefix ++ "ssl_sess.c",
    libssl_src_prefix ++ "ssl_sigalgs.c",
    libssl_src_prefix ++ "ssl_srvr.c",
    libssl_src_prefix ++ "ssl_stat.c",
    libssl_src_prefix ++ "ssl_tlsext.c",
    libssl_src_prefix ++ "ssl_transcript.c",
    libssl_src_prefix ++ "ssl_txt.c",
    libssl_src_prefix ++ "ssl_versions.c",
    libssl_src_prefix ++ "t1_enc.c",
    libssl_src_prefix ++ "t1_lib.c",
    libssl_src_prefix ++ "tls_buffer.c",
    libssl_src_prefix ++ "tls_content.c",
    libssl_src_prefix ++ "tls_key_share.c",
    libssl_src_prefix ++ "tls_lib.c",
    libssl_src_prefix ++ "tls12_key_schedule.c",
    libssl_src_prefix ++ "tls12_lib.c",
    libssl_src_prefix ++ "tls12_record_layer.c",
    libssl_src_prefix ++ "tls13_client.c",
    libssl_src_prefix ++ "tls13_error.c",
    libssl_src_prefix ++ "tls13_handshake.c",
    libssl_src_prefix ++ "tls13_handshake_msg.c",
    libssl_src_prefix ++ "tls13_key_schedule.c",
    libssl_src_prefix ++ "tls13_legacy.c",
    libssl_src_prefix ++ "tls13_lib.c",
    libssl_src_prefix ++ "tls13_quic.c",
    libssl_src_prefix ++ "tls13_record.c",
    libssl_src_prefix ++ "tls13_record_layer.c",
    libssl_src_prefix ++ "tls13_server.c",
};

const libtls_include_paths = [_][]const u8{
    libssl_src_prefix,
    source_header_prefix ++ "compat",
    source_header_prefix,
};

const libtls_sources = [_][]const u8{
    libtls_src_prefix ++ "tls.c",
    libtls_src_prefix ++ "tls_bio_cb.c",
    libtls_src_prefix ++ "tls_client.c",
    libtls_src_prefix ++ "tls_config.c",
    libtls_src_prefix ++ "tls_conninfo.c",
    libtls_src_prefix ++ "tls_keypair.c",
    libtls_src_prefix ++ "tls_server.c",
    libtls_src_prefix ++ "tls_signer.c",
    libtls_src_prefix ++ "tls_ocsp.c",
    libtls_src_prefix ++ "tls_peer.c",
    libtls_src_prefix ++ "tls_util.c",
    libtls_src_prefix ++ "tls_verify.c",
};

const libtls_windows_sources = [_][]const u8{
    libtls_src_prefix ++ "compat/ftruncate.c",
    libtls_src_prefix ++ "compat/pread.c",
    libtls_src_prefix ++ "compat/pwrite.c",
};
