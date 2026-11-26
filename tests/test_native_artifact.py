"""Catch Android loader-incompatible native binaries and truncated artifacts."""
import importlib.util
from pathlib import Path
import struct
import unittest
import tempfile
import zipfile

path = Path(__file__).resolve().parents[1] / "scripts/verify_apk.py"
spec = importlib.util.spec_from_file_location("verify_apk", path)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def elf(alignment=16384, machine=183, virtual_offset=0):
    body = bytearray(256)
    body[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", body, 16, 3, machine, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", body, 64, 1, 5, 0, virtual_offset, virtual_offset, 256, 256, alignment)
    return bytes(body)


class NativeArtifactTests(unittest.TestCase):
    def test_real_arm64_loader_contract_accepts_16k_load_segment(self):
        result = validator.validate_elf(elf())
        self.assertEqual(result.get("machine"), "AArch64")
        self.assertEqual(result.get("load_segments"), 1)

    def test_rejects_4k_native_alignment_for_android16k_delivery(self):
        with self.assertRaises(ValueError): validator.validate_elf(elf(alignment=4096))

    def test_rejects_unmatched_file_and_virtual_load_alignment(self):
        with self.assertRaises(ValueError): validator.validate_elf(elf(virtual_offset=1))

    def test_rejects_wrong_abi(self):
        with self.assertRaises(ValueError): validator.validate_elf(elf(machine=62))

    def test_rejects_truncated_program_header(self):
        with self.assertRaises(ValueError): validator.validate_elf(elf()[:90])


class ApkDeliveryTests(unittest.TestCase):
    def archive(self, directory, aligned=True, complete=True, compressed=False):
        path = Path(directory) / "fixture.apk"
        names = ("libloft_ffi.so", "libgojni.so", "libjnidispatch.so") if complete else ("libloft_ffi.so",)
        with zipfile.ZipFile(path, "w") as archive:
            for name in names:
                entry = zipfile.ZipInfo("lib/arm64-v8a/" + name)
                entry.compress_type = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
                if aligned:
                    padding = (-(archive.fp.tell() + 30 + len(entry.filename.encode()))) % 16384
                    if padding < 4: padding += 16384
                    entry.extra = struct.pack("<HH", 0xD935, padding - 4) + bytes(padding - 4)
                archive.writestr(entry, elf())
        return path

    def test_accepts_complete_stored_16k_native_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            result = validator.verify_archive(self.archive(directory))
            self.assertEqual(result.get("result"), "PASS")

    def test_rejects_unaligned_native_zip_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): validator.verify_archive(self.archive(directory, aligned=False))

    def test_rejects_missing_go_or_jna_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): validator.verify_archive(self.archive(directory, complete=False))

    def test_rejects_compressed_native_direct_load(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): validator.verify_archive(self.archive(directory, compressed=True))


if __name__ == "__main__": unittest.main()
