import mmap
import os
import stat
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import fix
from fix import TARGET_ALIGN, patch

FILE_PATH = str(Path(fix.__file__).resolve())
LARGE_ALIGN = 0x200000


@pytest.fixture
def temp_elf(tmp_path: Path):
    return tmp_path / "test_binary"


def create_dummy_elf(path: Path, is_64bit: bool = True, p_align: int = LARGE_ALIGN):
    if is_64bit:
        # Ehdr64 + one Phdr64
        e_ident = b"\x7fELF\x02\x01\x01" + (b"\x00" * 9)
        elf_header = struct.pack("<16sHHIQQQIHHHHHH",
            e_ident, 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        # Phdr64: type, flags, offset, vaddr, paddr, filesz, memsz, align
        prog_header = struct.pack(
            "<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 100, 100, p_align
        )
    else:
        # Ehdr32 + one Phdr32
        e_ident = b"\x7fELF\x01\x01\x01" + (b"\x00" * 9)
        elf_header = struct.pack("<16sHHIIIIIHHHHHH",
            e_ident, 2, 3, 1, 0x8048000, 52, 0, 0, 52, 32, 1, 0, 0, 0)
        # Phdr32: type, offset, vaddr, paddr, filesz, memsz, flags, align
        prog_header = struct.pack(
            "<IIIIIIII", 1, 0, 0x8048000, 0x8048000, 100, 100, 5, p_align
        )

    path.write_bytes(elf_header + prog_header)


class TestPatchingLogic:
    def test_no_patch_needed(self, temp_elf: Path):
        create_dummy_elf(temp_elf, is_64bit=True, p_align=TARGET_ALIGN)

        with (
            Path.open(temp_elf, "r+b") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as data
        ):
            changed = patch(data, write=True)

        assert changed is False

    def test_multiple_segments_mixed_types(self, temp_elf: Path):
        """Test that only PT_LOAD segments are patched in a multi-segment ELF."""
        e_ident = b"\x7fELF\x02\x01\x01" + (b"\x00" * 9)
        phnum = 3
        phoff = 64
        phentsize = 56

        # Ehdr64
        elf_header = struct.pack("<16sHHIQQQIHHHHHH",
            e_ident, 2, 62, 1, 0x400000, phoff, 0, 0, 64, phentsize, phnum, 0, 0, 0)

        # Segment 0: PT_PHDR (Type 6), Align 0x8
        seg0 = struct.pack("<IIQQQQQQ", 6, 4, 0, 0, 0, 100, 100, 0x8)
        # Segment 1: PT_LOAD (Type 1), Align 0x200000 -> TARGET
        seg1 = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 100, 100, 0x200000)
        # Segment 2: PT_LOAD (Type 1), Align 0x10000 -> TARGET
        seg2 = struct.pack("<IIQQQQQQ", 1, 6, 0, 0, 0, 100, 100, 0x10000)

        temp_elf.write_bytes(elf_header + seg0 + seg1 + seg2)

        # Run the patch
        with (
            Path.open(temp_elf, "r+b") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as data
        ):
            patch(data, write=True)

        # Verification
        content = temp_elf.read_bytes()

        # Offset: phoff + (0 * phentsize) + p_align_offset(48) = 112
        val0: int = struct.unpack_from("<Q", content, 112)[0]
        assert val0 == 0x8
        # Offset: phoff + (1 * phentsize) + p_align_offset(48) = 168
        val1: int = struct.unpack_from("<Q", content, 168)[0]
        assert val1 == 0x1000
        # Offset: phoff + (2 * phentsize) + p_align_offset(48) = 224
        val2: int = struct.unpack_from("<Q", content, 224)[0]
        assert val2 == 0x1000


class TestBinaryVariants:
    @pytest.mark.parametrize(
        ("is_64bit", "expected_offset", "format_char"),
        [
            (True, 112, "Q"),  # 64-bit: Header(64) + p_align_offset(48) = 112
            (False, 80, "I"),  # 32-bit: Header(52) + p_align_offset(28) = 80
        ],
    )
    def test_patch_alignment_variants(self, temp_elf: Path, is_64bit: bool, expected_offset: int, format_char: str):
        # 1. Setup: Create a file with 2MB alignment
        create_dummy_elf(temp_elf, is_64bit=is_64bit, p_align=LARGE_ALIGN)

        # 2. Act: Run the patch
        with (
            Path.open(temp_elf, "r+b") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as data
        ):
            changed = patch(data, write=True)

        # 3. Assert: Verify the logic reports a change
        assert changed is True

        # 4. Assert: Verify the actual bytes in the file are now 0x1000
        file_content = temp_elf.read_bytes()
        # Unpack based on the specific architecture's offset and size
        actual_val: int = struct.unpack_from(
            f"<{format_char}", file_content, expected_offset
        )[0]
        assert actual_val == TARGET_ALIGN

    def test_big_endian_elf(self, temp_elf: Path):
        # Byte 5 = 2 means Big-Endian
        e_ident = b"\x7fELF\x02\x02\x01" + (b"\x00" * 9)
        # Header fields packed with '>'
        elf_header = struct.pack(">16sHHIQQQIHHHHHH",
            e_ident, 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        # p_align is at the end of the 56-byte Phdr
        prog_header = struct.pack(">IIQQQQQQ", 1, 5, 0, 0, 0, 100, 100, 0x200000)

        temp_elf.write_bytes(elf_header + prog_header)

        with (
            Path.open(temp_elf, "r+b") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as data
        ):
            patch(data, write=True)

        # Verify the value was written in Big-Endian format
        val: int = struct.unpack_from(">Q", temp_elf.read_bytes(), 112)[0]
        assert val == TARGET_ALIGN

    def test_phnum_overflow_detection(self, temp_elf: Path, capsys: pytest.CaptureFixture[str]):
        # Offsets: phoff=64, shoff=120, phentsize=56, phnum=0xffff
        header = struct.pack("<16sHHIQQQIHHHHHH",
            b"\x7fELF\x02\x01\x01", 2, 62, 1, 0x40, 64, 120, 0, 64, 56, 0xffff, 64, 1, 0)

        # Phdr: PT_LOAD(1), flags(0), offset(0), vaddr(0), paddr(0), filesz(0), memsz(0), align(0x2000)
        phdr = struct.pack("<IIQQQQQQ", 1, 0, 0, 0, 0, 0, 0, 0x2000)

        # Shdr (Index 0): sh_name, type, flags, addr, offset, size, link, info (real phnum), ...
        # We only care about sh_info at offset 44
        sh_null = b"\x00" * 44 + struct.pack("<I", 1) + b"\x00" * 16

        temp_elf.write_bytes(header + phdr + sh_null)

        with (
            Path.open(temp_elf, "r+b") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as data
        ):
            changed = patch(data, write=False) # print the Large phnum
            assert changed is True

            patch(data, write=True)

            # Verify the align was changed to 0x1000
            # Phdr is at offset 64, p_align is at +48 within Phdr = 112
            new_align = struct.unpack_from("<Q", data, 112)[0]
            assert new_align == TARGET_ALIGN

        captured = capsys.readouterr()
        assert "Large phnum" in captured.out


class TestMemorySafety:
    def test_read_only_mmap(self, temp_elf: Path):
        # 1. Setup: Create a 64-bit ELF with high alignment (needs patching)
        create_dummy_elf(temp_elf, is_64bit=True, p_align=LARGE_ALIGN)

        # 2. Act & Assert
        with (
            Path.open(temp_elf, "rb") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data
        ):
            # This should identify that a fix is needed but NOT attempt to write
            # because write=False.
            needs_fix = patch(data, write=False)

            assert needs_fix is True, "Should identify that the ELF needs a fix"

            # Double check: Ensure the bytes in the mmap haven't changed
            # (Offset 112 is p_align for 64-bit in our create_dummy_elf)
            current_val: int = struct.unpack_from("<Q", data, 112)[0]
            assert (
                current_val == LARGE_ALIGN
            ), "Data was modified in a read-only map!"

    def test_read_only_mmap_write_failure(self, temp_elf: Path):
        create_dummy_elf(temp_elf, is_64bit=True, p_align=LARGE_ALIGN)

        with (
            Path.open(temp_elf, "rb") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data,
            # This should fail because pack_into cannot write to read-only mmap
            pytest.raises(TypeError)
        ):
            patch(data, write=True)

    def test_truncated_elf_table(self, temp_elf: Path):
        # 1. Create a 64-bit ELF header
        e_ident = b"\x7fELF\x02\x01\x01" + (b"\x00" * 9)
        # We claim:
        # e_phoff = 64 (headers start at byte 64)
        # e_phnum = 10 (we claim there are 10 headers)
        # e_phentsize = 56
        # Total table size should be 560 bytes.
        elf_header = struct.pack("<16sHHIQQQIHHHHHH",
            e_ident, 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 10, 0, 0, 0)

        # 2. Write ONLY the header (64 bytes) to the file.
        # The file is now way too small to contain the 10 headers it claims to have.
        temp_elf.write_bytes(elf_header)

        # 3. Attempt to patch
        with (
            Path.open(temp_elf, "rb") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data,
            # mmap might fail if the file is too small for the offsets,
            # or your patch() function's safety check should catch it.
            pytest.raises(IOError, match="Malformed ELF")
        ):
            patch(data, write=False)

    def test_invalid_elf(self, temp_elf: Path):
        temp_elf.write_bytes(b"NOT_AN_ELF_FILE_FOR_SURE")

        with (
            Path.open(temp_elf, "rb") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data,
            pytest.raises(IOError, match="Not a valid ELF file")
        ):
            patch(data, write=False)

    def test_file_integrity_after_patch(self, temp_elf: Path):
        create_dummy_elf(temp_elf, is_64bit=True, p_align=LARGE_ALIGN)
        original_size = temp_elf.stat().st_size

        with (
            Path.open(temp_elf, "r+b") as f,
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as data
        ):
            patch(data, write=True)

        assert temp_elf.stat().st_size == original_size
        assert temp_elf.read_bytes().startswith(b"\x7fELF")


class TestCommandLineInterface:
    def test_cli_backup_and_restore(self, temp_elf: Path):
        # 1. Setup: Create ELF and make it executable (0o755)
        create_dummy_elf(temp_elf, p_align=LARGE_ALIGN)
        temp_elf.chmod(temp_elf.stat().st_mode | stat.S_IXUSR)

        # 2. Act: Run the patch via CLI
        # Use sys.executable to ensure we use the right Python environment
        subprocess.run([sys.executable, FILE_PATH, str(temp_elf)], check=True)

        # 3. Assert: Check the Patch and Permissions
        content = temp_elf.read_bytes()
        # For 64-bit: e_phoff (at 32) + p_align_offset (48) = 80 bytes from start of Phdr
        actual_val: int = struct.unpack_from("<Q", content, 112)[0]

        assert actual_val == TARGET_ALIGN
        assert temp_elf.stat().st_mode & stat.S_IXUSR, "Lost executable bit!"
        assert temp_elf.with_suffix(".bak").exists(), "Backup missing!"

        # 4. Act: Restore
        subprocess.run(
            [sys.executable, FILE_PATH, str(temp_elf), "--restore"], check=True
        )

        # 5. Assert: Back to original
        restored_val: int = struct.unpack_from("<Q", temp_elf.read_bytes(), 112)[0]
        assert restored_val == LARGE_ALIGN

    @pytest.mark.skipif(
        os.name != "posix" or os.getuid() == 0,
        reason="Root user bypasses permission bits; test only valid for non-root on POSIX"
    )
    def test_permission_denied(self, temp_elf: Path):
        create_dummy_elf(temp_elf, p_align=0x200000)

        try:
            temp_elf.chmod(0o444)  # Read-only

            result = subprocess.run(
                [sys.executable, FILE_PATH, str(temp_elf)],
                capture_output=True,
                text=True,
                check=False
            )

            assert result.returncode == 1
            assert "denied" in result.stdout

        finally:
            if temp_elf.exists():
                temp_elf.chmod(0o666)

    def test_empty_file(self, temp_elf: Path):
        # Create a 0-byte file
        temp_elf.write_bytes(b"")

        result = subprocess.run(
            [sys.executable, FILE_PATH, str(temp_elf)],
            capture_output=True,
            text=True,
            check=False
        )

        assert result.returncode == 1
        assert "empty" in result.stdout

    def test_missing_file(self):
        result = subprocess.run(
            [sys.executable, FILE_PATH, "this_file_does_not_exist.bin"],
            capture_output=True,
            text=True,
            check=False
        )

        assert result.returncode == 1
        assert "not exist" in result.stdout

    def test_backup_overwrite_protection(self, temp_elf: Path):
        create_dummy_elf(temp_elf, p_align=LARGE_ALIGN)

        # Manually create a dummy backup file
        backup_path = temp_elf.with_suffix(".bak")
        backup_path.write_text("I am an old backup")

        # Try to run the script without -o
        result = subprocess.run(
            [sys.executable, FILE_PATH, str(temp_elf)],
            capture_output=True,
            text=True,
            check=False
        )

        assert result.returncode == 1
        assert "-o" in result.stdout

    def test_symlink_behavior(self, tmp_path: Path):
        real_bin = tmp_path / "real_binary"
        link_bin = tmp_path / "link_binary"
        create_dummy_elf(real_bin, p_align=LARGE_ALIGN)
        link_bin.symlink_to(real_bin)

        subprocess.run([sys.executable, FILE_PATH, str(link_bin)], check=True)

        # The real file should be patched
        val: int = struct.unpack_from("<Q", real_bin.read_bytes(), 112)[0]
        assert val == TARGET_ALIGN

    def test_custom_subdirectory_backup(self, temp_elf: Path, tmp_path: Path):
        create_dummy_elf(temp_elf, p_align=LARGE_ALIGN)
        custom_backup = tmp_path / "archive" / "nested" / "backup.old"

        subprocess.run([
            sys.executable, FILE_PATH, str(temp_elf),
            "-b", str(custom_backup)
        ], check=True)

        assert custom_backup.exists()
        assert custom_backup.parent.name == "nested"
