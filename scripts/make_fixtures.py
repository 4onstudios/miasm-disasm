"""Create deterministic, harmless PE32, PE32+, ELF64 and raw-code fixtures.

No compiler is required. These files exist for static inspection, not deployment.
The PE files have no imports, relocations, debug information, or CRT startup.
"""
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1] / "examples"
FUNCTION = bytes.fromhex("85c9 7e04 8d4101 c3 31c0 c3")
# Entry: ECX=5; call function; ret. Pad to function at offset 0x10.
CODE = bytes.fromhex("b905000000 e806000000 c3 cccccccccc") + FUNCTION


def pe(bits):
    optional_size = 240 if bits == 64 else 224
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x20B if bits == 64 else 0x10B)
    struct.pack_into("<I", optional, 4, 0x200)
    struct.pack_into("<II", optional, 16, 0x1000, 0x1000)
    if bits == 64:
        struct.pack_into("<Q", optional, 24, 0x140000000)
        struct.pack_into("<QQQQ", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<I", optional, 108, 16)
    else:
        struct.pack_into("<II", optional, 24, 0, 0x400000)
        struct.pack_into("<IIII", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<I", optional, 92, 16)
    struct.pack_into("<II", optional, 32, 0x1000, 0x200)
    struct.pack_into("<HH", optional, 40, 6, 0)
    struct.pack_into("<HH", optional, 48, 6, 0)
    struct.pack_into("<II", optional, 56, 0x2000, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if bits == 64 else 0x14C,
                     1, 0, 0, 0, optional_size, 0x22 if bits == 64 else 0x102)
    data[0x98:0x98 + optional_size] = optional
    struct.pack_into("<8sIIIIIIHHI", data, 0x98 + optional_size, b".text\0\0\0", len(CODE),
                     0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    return bytes(data) + CODE.ljust(0x200, b"\0")


def elf():
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0x401000,
                         64, 0, 0, 64, 56, 1, 0, 0, 0)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0x1000, 0x401000,
                          0x401000, len(CODE), len(CODE), 0x1000)
    return (header + program).ljust(0x1000, b"\0") + CODE


def main():
    ROOT.mkdir(exist_ok=True)
    files = {"sample64.exe": pe(64), "sample32.exe": pe(32), "sample.elf": elf(),
             "branch.bin": FUNCTION, "aarch64.bin": bytes.fromhex("20040011 c0035fd6"),
             "overlap.bin": bytes.fromhex("90 90 75fd c3")}
    for name, data in files.items():
        (ROOT / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
