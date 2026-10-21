"""Run inside the MCP image with the repository mounted at /workspace."""

from contextlib import asynccontextmanager
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from python import mcp_server


class PathTests(unittest.TestCase):
    def test_listing_metadata_navigation_and_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.bin").write_bytes(b"\x90\xc3")
            (root / "nested").mkdir()
            (root / "nested" / "child.bin").write_bytes(b"\xc3")
            (root / "empty").mkdir()
            with patch.object(mcp_server, "INPUT_ROOT", root):
                listing = mcp_server.list_files()
                self.assertEqual(listing["directory"], ".")
                self.assertFalse(listing["truncated"])
                self.assertEqual(listing["entries"], [
                    {"path": "empty", "type": "directory"},
                    {"path": "nested", "type": "directory"},
                    {"path": "sample.bin", "type": "file", "size_bytes": 2},
                ])
                limited = mcp_server.list_files(limit=1)
                self.assertEqual(len(limited["entries"]), 1)
                self.assertTrue(limited["truncated"])
                nested = mcp_server.list_files("nested", limit=1)
                self.assertEqual(nested["entries"], [
                    {"path": "nested/child.bin", "type": "file", "size_bytes": 1},
                ])
                self.assertFalse(nested["truncated"])
                self.assertEqual(mcp_server.list_files("empty")["entries"], [])

    def test_listing_rejects_escapes_and_omits_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "samples"
            root.mkdir()
            outside = Path(directory) / "outside.bin"
            outside.write_bytes(b"\xc3")
            (root / "escape.bin").symlink_to(outside)
            (root / "escape-dir").symlink_to(root.parent, target_is_directory=True)
            (root / "regular.bin").write_bytes(b"\xc3")
            with patch.object(mcp_server, "INPUT_ROOT", root):
                listing = mcp_server.list_files()
                self.assertEqual(listing["entries"], [
                    {"path": "regular.bin", "type": "file", "size_bytes": 1},
                ])
                for target in ["..", str(root.parent), "escape-dir", "missing", "regular.bin"]:
                    with self.subTest(directory=target):
                        with self.assertRaises(ValueError):
                            mcp_server.list_files(target)
                for limit in [0, 1001]:
                    with self.subTest(limit=limit):
                        with self.assertRaises(ValueError):
                            mcp_server.list_files(limit=limit)

    def test_symlink_cannot_escape_input_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "samples"
            root.mkdir()
            outside = Path(directory) / "outside.bin"
            outside.write_bytes(b"\xc3")
            (root / "escape.bin").symlink_to(outside)
            with patch.object(mcp_server, "INPUT_ROOT", root):
                with self.assertRaisesRegex(ValueError, "inside"):
                    mcp_server.sample_path("escape.bin")


@asynccontextmanager
async def protocol_session():
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["/opt/miasm/mcp_server.py"],
        env=dict(os.environ),
    )
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            yield session


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_tools_and_backend(self):
        async with protocol_session() as session:
            tools = await session.list_tools()
            self.assertEqual(
                {tool.name for tool in tools.tools},
                {"doctor", "list_files", "disassemble"},
            )
            result = await session.call_tool("doctor", {})
            self.assertFalse(result.isError)
            self.assertIn("x86_64", result.structuredContent["architectures"])

    async def test_pe_control_flow(self):
        async with protocol_session() as session:
            listing = await session.call_tool("list_files", {})
            self.assertFalse(listing.isError)
            sample = next(
                entry for entry in listing.structuredContent["entries"]
                if entry["path"] == "sample64.exe"
            )
            self.assertEqual(sample["type"], "file")
            self.assertGreater(sample["size_bytes"], 0)
            result = await session.call_tool(
                "disassemble", {"file": sample["path"], "follow_calls": True}
            )
            self.assertFalse(result.isError)
            self.assertEqual(result.structuredContent["instruction_count"], 9)
            self.assertEqual(len(result.structuredContent["blocks"]), 5)

    async def test_listing_limits_and_invalid_requests(self):
        async with protocol_session() as session:
            result = await session.call_tool("list_files", {"limit": 1})
            self.assertFalse(result.isError)
            self.assertEqual(len(result.structuredContent["entries"]), 1)
            self.assertTrue(result.structuredContent["truncated"])
            for arguments in [
                {"directory": ".."},
                {"directory": "/etc"},
                {"directory": "sample64.exe"},
                {"directory": "missing"},
                {"limit": 0},
                {"limit": 1001},
            ]:
                with self.subTest(arguments=arguments):
                    result = await session.call_tool("list_files", arguments)
                    self.assertTrue(result.isError)

    async def test_raw_architectures_and_addresses(self):
        async with protocol_session() as session:
            for file, arch, count in [
                ("branch.bin", "x86_64", 6),
                ("aarch64.bin", "aarch64l", 2),
            ]:
                with self.subTest(arch=arch):
                    result = await session.call_tool(
                        "disassemble",
                        {"file": file, "raw": True, "arch": arch, "base": "0x9000"},
                    )
                    self.assertFalse(result.isError)
                    self.assertEqual(result.structuredContent["entry_point"], 0x9000)
                    self.assertEqual(result.structuredContent["instruction_count"], count)

    async def test_partial_result(self):
        async with protocol_session() as session:
            result = await session.call_tool(
                "disassemble", {"file": "sample64.exe", "max_instructions": 1}
            )
            self.assertFalse(result.isError)
            self.assertTrue(result.structuredContent["truncated"])

    async def test_invalid_requests_are_tool_errors(self):
        async with protocol_session() as session:
            for arguments in [
                {"file": "../etc/passwd"},
                {"file": "/etc/passwd"},
                {"file": "missing.exe"},
                {"file": "."},
                {"file": "sample64.exe", "timeout": 121},
                {"file": "sample64.exe", "max_blocks": 1001},
                {"file": "sample64.exe", "max_instructions": 10001},
                {"file": "sample64.exe", "raw": True},
                {"file": "sample64.exe", "base": "0x9000"},
                {"file": "sample64.exe", "start": "-1"},
                {"file": "sample64.exe", "start": "0x10000000000000000"},
                {"file": "sample64.exe", "mode": "invalid"},
            ]:
                with self.subTest(arguments=arguments):
                    result = await session.call_tool("disassemble", arguments)
                    self.assertTrue(result.isError)


if __name__ == "__main__":
    unittest.main()