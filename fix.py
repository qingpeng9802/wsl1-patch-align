#!/usr/bin/env python3

"""
Fix the issue caused by the assumption of `p_align` on WSL 1

https://github.com/microsoft/WSL/issues/8219
https://github.com/microsoft/WSL/issues/8151
https://github.com/microsoft/WSL/issues/12359

Root cause: https://github.com/microsoft/WSL/issues/8219#issuecomment-1094123281
Idea is from and inspired by https://github.com/microsoft/WSL/issues/8219#issuecomment-1133936081
"""

import argparse
import mmap
import os
import shutil
import struct
import sys
from pathlib import Path
from typing import Final, TypedDict

COL: Final[bool] = (
    sys.stdout.isatty()
    and not os.getenv("NO_COLOR")
    and os.getenv("TERM", "dumb").lower() != "dumb"
)
BLUE: Final = "\033[1;34m" if COL else ""
RED: Final = "\033[1;31m" if COL else ""
NC: Final = "\033[0m" if COL else ""
LOG_TITLE: Final = f"{BLUE}[p_align]{NC}"
ERR_TITLE: Final = f"{RED}[p_align]{NC}"

PT_LOAD: Final = 1
PN_XNUM: Final = 0xffff
TARGET_ALIGN: Final = 0x1000

class ELFOffsets(TypedDict):
    ph_table_start: int
    entry_size: int
    entry_count: int
    p_align_offset: int
    fmt: str

ELF32: Final = ELFOffsets(
    ph_table_start=28,  # e_phoff      Program header table's file offset in bytes
    entry_size=42,      # e_phentsize  ELF header's size in bytes
    entry_count=44,     # e_phnum      Number of entries in the program header table
    p_align_offset=28,  # Offset of p_align within Program header (Phdr)
    fmt="I",  # 4-byte unsigned int
)

ELF64: Final = ELFOffsets(
    ph_table_start=32,
    entry_size=54,
    entry_count=56,
    p_align_offset=48,
    fmt="Q",  # 8-byte unsigned long long
)


def validate_paths(path: Path, backup: Path, overwrite: bool):
    if not path.exists():
        raise FileNotFoundError(f"Target file '{path}' does not exist.")

    if not path.is_file():
        raise IsADirectoryError(f"'{path}' is a directory, not a file.")

    if backup.exists() and not overwrite:
        raise FileExistsError(f"Backup '{backup}' already exists. Use -o to overwrite.")


def get_backup_path(path: Path, backup_str: str | None = None):
    default_backup = path.with_suffix(path.suffix + ".bak")
    if backup_str is None:
        return default_backup

    backup = Path(backup_str)
    if backup_str.endswith(os.sep) or backup.is_dir():
        return backup / default_backup.name
    return backup


def patch_data(data: mmap.mmap, write: bool) -> bool:
    # 1. Check bytes for validation, arch and endian
    if data[:4] != b"\x7fELF":
        raise OSError(
            f"Error: Not a valid ELF file. Expected first 4 bytes: 7f 45 4c 46\n"
            f"Received first 16 bytes (hex): {data[:16].hex(' ')}\n"
            f"Received first 16 bytes (raw): {repr(data[:16])}\n"
        )
    # Byte 4: 1 is 32-bit, 2 is 64-bit
    is_64bit = data[4] == 2
    offsets = ELF64 if is_64bit else ELF32
    # Byte 5: 1 = Little Endian (<), 2 = Big Endian (>)
    endian = ">" if data[5] == 2 else "<"
    if not write:
        print(
            f"{LOG_TITLE} Detected {'64-bit' if is_64bit else '32-bit'} "
            f"{'Big' if data[5] == 2 else 'Little'}-Endian ELF"
        )

    # 2. Parse Header Info
    def get_val(pos: int, fmt: str) -> int:
        return struct.unpack_from(f"{endian}{fmt}", data, pos)[0]

    # 'H' is a 2-byte unsigned short (used for sizes/counts in both archs)
    phoff = get_val(offsets["ph_table_start"], offsets["fmt"])
    phentsize = get_val(offsets["entry_size"], "H")
    phnum = get_val(offsets["entry_count"], "H")

    if phnum == PN_XNUM:
        # e_shoff is located at offset 32 (ELF32) or 40 (ELF64)
        shoff_pos = 40 if is_64bit else 32
        shoff_fmt = "Q" if is_64bit else "I"
        shoff = get_val(shoff_pos, shoff_fmt)

        if shoff == 0:
            raise OSError("ELF header indicates PN_XNUM, but Section Header Table offset is 0.")

        # The true phnum is in the first Shdr's sh_info field
        # sh_info is at offset 28 (ELF32) or 44 (ELF64) from the start of the Shdr
        sh_info_offset = 44 if is_64bit else 28
        if shoff + sh_info_offset + 4 > len(data):
            raise OSError("Malformed ELF: Section Header Table exceeds file size.")
        phnum = get_val(shoff + sh_info_offset, "I")
        if not write:
            print(f"{LOG_TITLE} Large phnum detected. Real count: {phnum}")

    table_end = phoff + (phnum * phentsize)
    if table_end > len(data):
        raise OSError(
            f"Malformed ELF: Program Header Table (ends at {table_end}) "
            f"exceeds file size ({len(data)})."
        )

    # 3. Find and Patch Segments
    changed = False
    for i in range(phnum):
        # Calculate the start of this specific segment header
        entry_pos = phoff + (i * phentsize)

        # PT_LOAD is always a 4-byte 'I' at the start of the entry
        segment_type = get_val(entry_pos, "I")
        if segment_type == PT_LOAD:
            align_pos = entry_pos + offsets["p_align_offset"]
            current_align = get_val(align_pos, offsets["fmt"])

            if current_align != TARGET_ALIGN:
                if write:
                    print(
                        f"{LOG_TITLE} Patching segment {i}: {hex(current_align)} -> {hex(TARGET_ALIGN)}"
                    )
                    struct.pack_into(
                        f"{endian}{offsets['fmt']}", data, align_pos, TARGET_ALIGN
                    )
                changed = True

    return changed


def fix_elf(file_path: Path, backup_path: Path, overwrite: bool = False):
    validate_paths(file_path, backup_path, overwrite)

    if file_path.stat().st_size == 0:
        raise ValueError(f"'{file_path}' is an empty file.")

    # Scan first to see if needs to fix
    with (
        Path.open(file_path, "rb") as f,
        mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data
    ):
        needs_fix = patch_data(data, write=False)

    if not needs_fix:
        print(f"{LOG_TITLE} No changes needed.")
        return

    print(f"{LOG_TITLE} Creating backup at: {backup_path}")
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(file_path, backup_path)

    try:
        with (
            Path.open(file_path, "r+b") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as data
        ):
            patch_data(data, write=True)
            # Flush changes to disk
            data.flush()
            os.fsync(f.fileno())

        print(f"{LOG_TITLE} Done! Executable patched successfully.")

    except Exception as e:
        print(f"{ERR_TITLE} Patching failed! Attempting to restore from backup")
        restore_file(file_path, backup_path)
        raise e


def restore_file(file_path: Path, backup_path: Path):
    if not backup_path.exists():
        raise FileNotFoundError(f"Backup file '{backup_path}' not found.")

    print(f"{LOG_TITLE} Restoring '{backup_path}' -> '{file_path}'")
    shutil.copy2(backup_path, file_path)
    print(f"{LOG_TITLE} Restore complete.")


def get_binary_path(target: str, file: bool, command: bool):
    raw_path = None

    if file:
        raw_path = Path(target)
    elif command:
        cmd_location = shutil.which(target)
        raw_path = Path(cmd_location) if cmd_location else None
    else:
        if os.sep in target:
            raw_path = Path(target)
        else:
            cmd_location = shutil.which(target)
            raw_path = Path(cmd_location) if cmd_location else None

    if not raw_path or not raw_path.exists():
        raise FileNotFoundError(f"Error: Could not find '{target}' as a file or system command.")

    print(f"{LOG_TITLE} Found target file: {raw_path}")
    final_path = raw_path.resolve()

    if raw_path != final_path:
        print(f"{LOG_TITLE} Symlink detected: {raw_path} -> patching: {final_path}")

    return final_path


def main():
    parser = argparse.ArgumentParser(
        description="Fix ELF p_align for WSL 1 compatibility."
    )

    parser.add_argument("target", help="The file path to the binary or command name to fix")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-f", "--file", action="store_true", help="Explicitly treat input as a file path")
    mode.add_argument("-c", "--command", action="store_true", help="Explicitly treat input as a command name")

    parser.add_argument(
        "-r", "--restore", action="store_true", help="Restore the file from the backup"
    )
    parser.add_argument("-b", "--backup", help="Customized backup path")
    parser.add_argument(
        "-o", "--overwrite", action="store_true", help="Overwrite existing backup"
    )

    args = parser.parse_args()

    try:
        target_path = get_binary_path(args.target, args.file, args.command)
        target_backup = get_backup_path(target_path, args.backup)

        if args.restore:
            if args.overwrite:
                parser.error("Option --overwrite is only valid when fixing a file, not when using --restore")
            restore_file(target_path, target_backup)
        else:
            fix_elf(target_path, target_backup, args.overwrite)

    except (FileNotFoundError, IsADirectoryError, FileExistsError) as e:
        print(f"{ERR_TITLE} File Error: {e}")
        sys.exit(1)

    except PermissionError:
        print(f"{ERR_TITLE} Permission denied. Try running with 'sudo'.")
        sys.exit(1)

    except (OSError, ValueError) as e:
        # ValueError: Used for "Empty file" or logic issues
        # OSError: Used for "Not a valid ELF" or "Malformed ELF"
        print(f"{ERR_TITLE} Patch Error: {e}")
        sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n{ERR_TITLE} Operation cancelled by user.")
        sys.exit(1)

    except Exception as e:
        # The 'Catch-All' for things we didn't foresee (bugs)
        print(f"{ERR_TITLE} An unexpected critical error occurred: {e}")
        # If you want the full technical details for debugging, uncomment:
        # import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
