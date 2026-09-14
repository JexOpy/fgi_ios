"""
Pure Python Mach-O binary manipulation.
Replaces the Mac-only `insert_dylib` tool — works on Windows, Linux, and Mac.

This module can:
- Parse Mach-O headers (single-arch and FAT/universal binaries)
- Strip LC_CODE_SIGNATURE load commands
- Insert LC_LOAD_DYLIB load commands to load a dylib at runtime
"""

import struct
from pathlib import Path

from fgi_ios.logger import Logger

# Mach-O magic numbers
MH_MAGIC = 0xFEEDFACE  # 32-bit, native endian
MH_MAGIC_64 = 0xFEEDFACF  # 64-bit, native endian
MH_CIGAM = 0xCEFAEDFE  # 32-bit, swapped endian
MH_CIGAM_64 = 0xCFFAEDFE  # 64-bit, swapped endian

# FAT (universal) magic numbers (always big-endian)
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

# Load command types
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_CODE_SIGNATURE = 0x1D

# Struct sizes
MACH_HEADER_SIZE = 28  # 7 * uint32
MACH_HEADER_64_SIZE = 32  # 8 * uint32
FAT_HEADER_SIZE = 8  # 2 * uint32
FAT_ARCH_SIZE = 20  # 5 * uint32
DYLIB_COMMAND_HEADER_SIZE = 24  # cmd(4) + cmdsize(4) + name_offset(4) + timestamp(4) + current_version(4) + compat_version(4)


def _detect_format(data: bytes) -> tuple[str, bool]:
    """Detect Mach-O format. Returns (endian_char, is_64bit)."""
    magic = struct.unpack("<I", data[:4])[0]
    if magic == MH_MAGIC:
        return "<", False
    elif magic == MH_MAGIC_64:
        return "<", True
    elif magic == MH_CIGAM:
        return ">", False
    elif magic == MH_CIGAM_64:
        return ">", True
    else:
        raise ValueError(f"Unknown Mach-O magic: 0x{magic:08X}")


def _is_fat(data: bytes) -> bool:
    """Check if binary is a FAT/universal binary."""
    magic = struct.unpack(">I", data[:4])[0]
    return magic == FAT_MAGIC


def _round_up(value: int, alignment: int) -> int:
    """Round up value to the nearest multiple of alignment."""
    return (value + alignment - 1) & ~(alignment - 1)


def _process_single_macho(data: bytearray, offset: int, dylib_path: str, strip_codesig: bool) -> None:
    """Process a single Mach-O binary (within a FAT slice or standalone)."""
    endian, is_64 = _detect_format(bytes(data[offset : offset + 4]))
    header_size = MACH_HEADER_64_SIZE if is_64 else MACH_HEADER_SIZE
    ptr_size = 8 if is_64 else 4

    # Read header fields
    if is_64:
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
            f"{endian}IiiIIIII", data, offset
        )
    else:
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            f"{endian}IiiIIII", data, offset
        )

    Logger.debug(f"  Mach-O at offset 0x{offset:X}: {'64-bit' if is_64 else '32-bit'}, {ncmds} load commands, sizeofcmds={sizeofcmds}")

    commands_offset = offset + header_size
    lc_offset = commands_offset

    # Walk load commands to find LC_CODE_SIGNATURE and check for existing dylib
    codesig_offset = -1
    codesig_cmdsize = 0
    codesig_index = -1
    first_segment_fileoff = -1

    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from(f"{endian}II", data, lc_offset)

        # Check if this dylib is already loaded
        if cmd == LC_LOAD_DYLIB or cmd == LC_LOAD_WEAK_DYLIB:
            name_offset_val = struct.unpack_from(f"{endian}I", data, lc_offset + 8)[0]
            name_start = lc_offset + name_offset_val
            name_end = data.index(0, name_start)
            existing_name = data[name_start:name_end].decode("utf-8", errors="replace")
            if existing_name == dylib_path:
                Logger.warn(f"  Dylib '{dylib_path}' is already loaded, skipping")
                return

        # Track LC_CODE_SIGNATURE
        if cmd == LC_CODE_SIGNATURE:
            codesig_offset = lc_offset
            codesig_cmdsize = cmdsize
            codesig_index = i

        # Track first segment file offset (to know available space)
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            if cmd == LC_SEGMENT_64:
                seg_fileoff = struct.unpack_from(f"{endian}Q", data, lc_offset + 40)[0]
            else:
                seg_fileoff = struct.unpack_from(f"{endian}I", data, lc_offset + 36)[0]
            if seg_fileoff > 0 and (first_segment_fileoff == -1 or seg_fileoff < first_segment_fileoff):
                first_segment_fileoff = seg_fileoff

        lc_offset += cmdsize

    # Strip LC_CODE_SIGNATURE if found and requested
    if strip_codesig and codesig_offset != -1:
        if codesig_index == ncmds - 1:
            Logger.debug(f"  Stripping LC_CODE_SIGNATURE ({codesig_cmdsize} bytes)")
            # Zero out the load command
            for j in range(codesig_cmdsize):
                data[codesig_offset + j] = 0
            ncmds -= 1
            sizeofcmds -= codesig_cmdsize
        else:
            Logger.warn("  LC_CODE_SIGNATURE is not the last load command, cannot strip safely")

    # Build the new LC_LOAD_DYLIB command
    dylib_path_bytes = dylib_path.encode("utf-8") + b"\x00"
    new_cmdsize = _round_up(DYLIB_COMMAND_HEADER_SIZE + len(dylib_path_bytes), ptr_size)

    # Check available space
    end_of_commands = commands_offset + sizeofcmds
    available_space = (first_segment_fileoff + offset if first_segment_fileoff > 0 else len(data)) - end_of_commands

    if new_cmdsize > available_space:
        Logger.fatal(
            f"  Not enough space to insert load command. "
            f"Need {new_cmdsize} bytes, only {available_space} available. "
            f"Try stripping code signature first with --strip-codesig."
        )
        return

    # Write the new load command at end of current commands
    insert_offset = end_of_commands
    new_lc = bytearray(new_cmdsize)

    struct.pack_into(f"{endian}I", new_lc, 0, LC_LOAD_DYLIB)  # cmd
    struct.pack_into(f"{endian}I", new_lc, 4, new_cmdsize)  # cmdsize
    struct.pack_into(f"{endian}I", new_lc, 8, DYLIB_COMMAND_HEADER_SIZE)  # name offset
    struct.pack_into(f"{endian}I", new_lc, 12, 0)  # timestamp
    struct.pack_into(f"{endian}I", new_lc, 16, 0)  # current_version
    struct.pack_into(f"{endian}I", new_lc, 20, 0)  # compatibility_version

    # Write the dylib path string
    new_lc[DYLIB_COMMAND_HEADER_SIZE : DYLIB_COMMAND_HEADER_SIZE + len(dylib_path_bytes)] = dylib_path_bytes

    # Insert into binary data
    data[insert_offset : insert_offset + new_cmdsize] = new_lc

    # Update header: ncmds and sizeofcmds
    ncmds += 1
    sizeofcmds += new_cmdsize

    if is_64:
        struct.pack_into(f"{endian}II", data, offset + 16, ncmds, sizeofcmds)
    else:
        struct.pack_into(f"{endian}II", data, offset + 12, ncmds, sizeofcmds)

    Logger.info(f"  Inserted LC_LOAD_DYLIB: {dylib_path}")


def inject_dylib(binary_path: Path, dylib_path: str, strip_codesig: bool = True) -> None:
    """
    Inject a dylib load command into a Mach-O binary.

    Args:
        binary_path: Path to the Mach-O binary to modify (modified in-place).
        dylib_path: The dylib path to inject (e.g. '@executable_path/Frameworks/FridaGadget.dylib').
        strip_codesig: Whether to strip LC_CODE_SIGNATURE first (recommended).
    """
    Logger.info(f"Injecting dylib into: {binary_path.name}")

    data = bytearray(binary_path.read_bytes())

    if _is_fat(data):
        # FAT/universal binary — process each architecture slice
        nfat_arch = struct.unpack(">I", data[4:8])[0]
        Logger.debug(f"FAT binary with {nfat_arch} architectures")

        for i in range(nfat_arch):
            arch_offset = FAT_HEADER_SIZE + i * FAT_ARCH_SIZE
            cputype, cpusubtype, slice_offset, slice_size, align = struct.unpack_from(
                ">iiIII", data, arch_offset
            )
            Logger.debug(f"  Slice {i}: cputype={cputype}, offset=0x{slice_offset:X}, size={slice_size}")
            _process_single_macho(data, slice_offset, dylib_path, strip_codesig)
    else:
        # Single-arch binary
        _process_single_macho(data, 0, dylib_path, strip_codesig)

    binary_path.write_bytes(data)
    Logger.info("Binary patched successfully")
