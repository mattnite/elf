//! ELF Parsing
//!
//! The types exported are generic. In general what I do is:
//!
//! - give them longer, more descriptive names
//! - any discrepancies between 32 and 64 bit means the type will be 64-bit
//! - add document comments to fields
const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const Class = enum(u8) {
    @"32-bit" = 1,
    @"64-bit" = 2,
};

pub const ExecutableHeader = struct {
    class: Class,
    endian: std.builtin.Endian,
    osabi: u8,
    abiversion: u8,

    type: std.elf.ET,
    machine: std.elf.EM,
    version: std.elf.Word,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: std.elf.Word,
    ehsize: std.elf.Half,
    phentsize: std.elf.Half,
    phnum: std.elf.Half,
    shentsize: std.elf.Half,
    shnum: std.elf.Half,
    shstrndx: std.elf.Half,
};

pub const SectionHeader = struct {
    name: std.elf.Word,
    type: std.elf.Word,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: std.elf.Word,
    info: std.elf.Word,
    addralign: u64,
    entsize: u64,
};

pub const File = struct {
    gpa: Allocator,
    inner: fs.File,
    ehdr: ExecutableHeader,
    section_headers: []SectionHeader,
    string_table: []u8,

    pub fn init(gpa: Allocator, file: fs.File) !File {
        const ehdr = try read_header(file);
        const section_headers = try read_section_headers(gpa, file, &ehdr);
        const string_table = try read_string_table(gpa, file, &ehdr, section_headers);
        return File{
            .gpa = gpa,
            .inner = file,
            .ehdr = ehdr,
            .section_headers = section_headers,
            .string_table = string_table,
        };
    }

    pub fn deinit(f: *File) void {
        f.gpa.free(f.section_headers);
        f.gpa.free(f.string_table);
    }

    pub fn get_section(f: *File, gpa: Allocator, name: []const u8) ![]const u8 {
        const header_idx = for (f.section_headers, 0..) |shdr, i| {
            if (i == f.ehdr.shstrndx)
                continue;

            const section_name = f.get_string(shdr.name);
            if (std.mem.eql(u8, name, section_name))
                break i;
        } else return error.SectionNotFound;

        return read_section(gpa, f.inner, &f.section_headers[header_idx]);
    }

    fn get_string(f: *File, offset: usize) []const u8 {
        const name_ptr: [*:0]const u8 = @ptrCast(&f.string_table[offset]);
        return std.mem.span(name_ptr);
    }

    fn read_header(file: fs.File) !ExecutableHeader {
        var buf: [4096]u8 = undefined;
        var file_reader = file.reader(&buf);
        try file_reader.seekTo(0);
        const reader = &file_reader.interface;

        const ident = try reader.takeArray(std.elf.EI_NIDENT);
        std.log.info("ident={any}", .{ident});

        const magic = ident[0..std.elf.MAGIC.len];
        if (!mem.eql(u8, magic, std.elf.MAGIC)) {
            return error.MagicFailed;
        }

        const class_int = ident[std.elf.EI_CLASS];
        std.log.info("class_int={}", .{class_int});
        const endian_int = ident[std.elf.EI_DATA];
        std.log.info("endian_int={}", .{endian_int});
        const version_int = ident[std.elf.EI_VERSION];
        std.log.info("version_int={}", .{version_int});
        const osabi_int = ident[std.elf.EI_OSABI];
        std.log.info("osabi_int={}", .{osabi_int});
        const abiversion_int = ident[std.elf.EI_ABIVERSION];
        std.log.info("abiversion_int={}", .{osabi_int});

        const class = try std.meta.intToEnum(Class, class_int);
        const endian = try std.meta.intToEnum(std.builtin.Endian, endian_int);
        if (version_int != 1) {
            return error.Invalid_ELF;
        }

        try file_reader.seekTo(0);
        return switch (class) {
            .@"32-bit" => blk: {
                const hdr = try reader.takeStruct(std.elf.Elf32_Ehdr, endian);
                break :blk ExecutableHeader{
                    .class = class,
                    .endian = endian,
                    .osabi = osabi_int,
                    .abiversion = abiversion_int,
                    .type = hdr.e_type,
                    .machine = hdr.e_machine,
                    .version = hdr.e_version,
                    .entry = hdr.e_entry,
                    .phoff = hdr.e_phoff,
                    .shoff = hdr.e_shoff,
                    .flags = hdr.e_flags,
                    .ehsize = hdr.e_ehsize,
                    .phentsize = hdr.e_phentsize,
                    .phnum = hdr.e_phnum,
                    .shentsize = hdr.e_shentsize,
                    .shnum = hdr.e_shnum,
                    .shstrndx = hdr.e_shstrndx,
                };
            },
            .@"64-bit" => blk: {
                const hdr = try reader.takeStruct(std.elf.Elf64_Ehdr, endian);
                break :blk ExecutableHeader{
                    .class = class,
                    .endian = endian,
                    .osabi = osabi_int,
                    .abiversion = abiversion_int,
                    .type = hdr.e_type,
                    .machine = hdr.e_machine,
                    .version = hdr.e_version,
                    .entry = hdr.e_entry,
                    .phoff = hdr.e_phoff,
                    .shoff = hdr.e_shoff,
                    .flags = hdr.e_flags,
                    .ehsize = hdr.e_ehsize,
                    .phentsize = hdr.e_phentsize,
                    .phnum = hdr.e_phnum,
                    .shentsize = hdr.e_shentsize,
                    .shnum = hdr.e_shnum,
                    .shstrndx = hdr.e_shstrndx,
                };
            },
        };
    }

    fn read_section_headers(gpa: Allocator, file: fs.File, ehdr: *const ExecutableHeader) ![]SectionHeader {
        const section_headers = try gpa.alloc(SectionHeader, ehdr.shnum);
        errdefer gpa.free(section_headers);
        for (section_headers, 0..) |*sh, i| {
            sh.* = try read_section_header(file, ehdr, i);
            std.log.info("shdr: {}", .{sh.*});
        }

        return section_headers;
    }

    fn read_section_header(file: fs.File, ehdr: *const ExecutableHeader, idx: usize) !SectionHeader {
        var buf: [4096]u8 = undefined;
        var file_reader = file.reader(&buf);

        const header_size: usize = switch (ehdr.class) {
            .@"32-bit" => @sizeOf(std.elf.Elf32_Shdr),
            .@"64-bit" => @sizeOf(std.elf.Elf64_Shdr),
        };

        const offset = ehdr.shoff + (idx * header_size);
        try file_reader.seekTo(offset);
        const reader = &file_reader.interface;

        return switch (ehdr.class) {
            .@"32-bit" => blk: {
                const hdr = try reader.takeStruct(std.elf.Elf32_Shdr, ehdr.endian);
                break :blk SectionHeader{
                    .name = hdr.sh_name,
                    .type = hdr.sh_type,
                    .flags = hdr.sh_flags,
                    .addr = hdr.sh_addr,
                    .offset = hdr.sh_offset,
                    .size = hdr.sh_size,
                    .link = hdr.sh_link,
                    .info = hdr.sh_info,
                    .addralign = hdr.sh_addralign,
                    .entsize = hdr.sh_entsize,
                };
            },
            .@"64-bit" => blk: {
                const hdr = try reader.takeStruct(std.elf.Elf64_Shdr, ehdr.endian);
                break :blk SectionHeader{
                    .name = hdr.sh_name,
                    .type = hdr.sh_type,
                    .flags = hdr.sh_flags,
                    .addr = hdr.sh_addr,
                    .offset = hdr.sh_offset,
                    .size = hdr.sh_size,
                    .link = hdr.sh_link,
                    .info = hdr.sh_info,
                    .addralign = hdr.sh_addralign,
                    .entsize = hdr.sh_entsize,
                };
            },
        };
    }

    fn read_section(gpa: Allocator, file: fs.File, shdr: *const SectionHeader) ![]u8 {
        var buf: [4096]u8 = undefined;
        var file_reader = file.reader(&buf);

        try file_reader.seekTo(shdr.offset);
        const reader = &file_reader.interface;

        const ret = try gpa.alloc(u8, shdr.size);
        errdefer gpa.free(ret);

        try reader.readSliceAll(ret);
        return ret;
    }

    fn read_string_table(gpa: Allocator, file: fs.File, ehdr: *const ExecutableHeader, section_headers: []const SectionHeader) ![]u8 {
        return read_section(gpa, file, &section_headers[ehdr.shstrndx]);
    }
};
