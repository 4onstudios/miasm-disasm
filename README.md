<p align="center">
    <img src="assets/logo.svg" width="120" height="132" alt="miasm-disasm: an M-shaped control-flow graph with an amber branch node">
</p>

# miasm-disasm

A Rust command-line disassembler and reusable Rust crate powered by
[Miasm](https://github.com/cea-sec/miasm). It reads Windows PE executables, ELF
files, and raw machine code, then produces assembly listings, structured JSON,
or Graphviz control-flow graphs.

**Miasm is the decoding engine.** This package is a Rust interface to its Python
API, not a reimplementation of Miasm in Rust. A small Python bridge is embedded
in the Rust executable and launched in a separate process for each request.
Python and Miasm remain runtime requirements. The package does static analysis;
it does not run or emulate the input executable.

## Install from this package

Requirements: Rust/Cargo 1.85 or newer and Python 3.10 or newer. Linux with Python
3.12 is the tested environment. Windows and macOS commands are included below;
they have not been executed as part of this build.

### Linux / macOS

Run these commands in the extracted project directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r python/requirements.txt
cargo install --path . --locked
export MIASM_PYTHON="$PWD/.venv/bin/python"
miasm-disasm doctor
miasm-disasm disasm examples/sample64.exe --follow-calls
```

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r python\requirements.txt
cargo install --path . --locked
$env:MIASM_PYTHON = (Resolve-Path .\.venv\Scripts\python.exe).Path
miasm-disasm doctor
miasm-disasm disasm .\examples\sample64.exe --follow-calls
```

`--python PATH` overrides `MIASM_PYTHON`. Without either, the default is `python3`
on Unix and `python` on Windows. Use an actual interpreter path, not a command
containing arguments such as `py -3`. Python runs in isolated mode (`-I`), so
`PYTHONPATH`, the current directory, and user site packages are not used to find
Miasm. Install it inside the selected virtual environment.

The requirements pin Miasm to upstream commit
`3671fc24d6e625c2d75f3311724eb6b0c97664f8`, plus its Python dependencies. This
snapshot has newer Python build support than the old PyPI 0.1.5 source release.
Disassembly does not require Miasm's optional native JIT extensions.

The package is supplied as source and a Cargo `.crate` archive. It has not been
published to crates.io. A standard Rust toolchain and linker must be installed
before building it; see [rustup](https://rustup.rs/).

## Use it

```sh
# Start at the Windows executable's entry point.
miasm-disasm disasm program.exe

# Include direct call destinations and produce structured JSON.
miasm-disasm disasm program.exe --follow-calls --format json -o result.json

# Disassemble a specific function by its virtual address.
miasm-disasm disasm program.exe --start 0x140001010

# Export a control-flow graph; rendering it requires Graphviz separately.
miasm-disasm disasm program.exe --follow-calls --format dot -o cfg.dot
dot -Tsvg cfg.dot -o cfg.svg

# Decode raw bytes with an explicit architecture and load address.
miasm-disasm disasm examples/branch.bin --raw --arch x86_64 --base 0x9000

# Linear ARM64 scan, including instructions after returns/branches.
miasm-disasm disasm examples/aarch64.bin --raw --arch aarch64l --mode linear

# Limit analysis and use exit code 3 when the result is partial.
miasm-disasm --timeout 10 disasm program.exe --max-blocks 50 \
  --max-instructions 1000 --fail-on-partial
```

`--start` and `--base` accept decimal or `0x` hexadecimal, with optional `_`
separators. They denote **virtual addresses**, never file offsets. PE addresses
include the preferred image base, not a process's ASLR-adjusted address.
For ELF PIE files, addresses use the link-time image values. `--base` is available
only with `--raw`. Raw input always requires `--arch`.

Output goes to stdout unless `-o` is used. Output files are created exclusively:
an existing file is never overwritten by `-o`.

### Modes and boundaries

| Setting | Behavior |
| --- | --- |
| `--mode cfg` (default) | Follow known branch destinations from the start address; stop at terminal instructions. |
| `--follow-calls` | Also visit direct call destinations in CFG mode. |
| `--mode linear` | Decode consecutive instructions until a decode error, raw-file end, or instruction limit; does not follow control flow. |
| `--max-blocks` | Default 256; maximum 10,000. Counts CFG decoding operations before Miasm splits overlapping blocks. Ignored in linear mode. |
| `--max-instructions` | Default 10,000; maximum 100,000. Applies to both modes. |
| `--timeout` | Default 30 seconds; range 1–3,600. A timeout kills the worker and returns an error. |
| Input/output bounds | Maximum input file size 64 MiB; each captured worker stream capped at 64 MiB. |

A limit returns available results with `truncated: true` and a warning. A later
decode failure returns available instructions with warnings. Failure to decode
the starting address is an error. `truncated: false` only means no configured
limit was hit; it does not prove that every possible runtime path was discovered.
`--fail-on-partial` considers both truncation and decode warnings.

Exit codes: `0` success (possibly partial by default), `1` input/backend/timeout
error, `2` CLI usage error, `3` partial output with `--fail-on-partial`.

Miasm advertises multiple architectures through `doctor`. This package has
integration coverage for x86-32, x86-64, and little-endian AArch64. Other names
are passed through to Miasm; available decoding engines depend on its build.
Native PE code is supported. Managed .NET IL is not decoded as IL. Packed,
self-modifying, encrypted code, indirect jumps, and dynamically resolved calls
need additional analysis. This is not a decompiler or automatic whole-program
function discovery tool. Machine-code listings do not reconstruct original
source, variable names, or types.

The worker is a separate process with limits, not an operating-system sandbox.
For unknown binaries, use an appropriately isolated analysis environment.

## Rust library

To use the local crate in another Rust project:

```toml
[dependencies]
miasm-disasm = { path = "../miasm-disasm" }
```

```rust,no_run
use miasm_disasm::{Disassembler, Options};
use std::time::Duration;

fn main() -> Result<(), miasm_disasm::Error> {
    let engine = Disassembler::new(".venv/bin/python")
        .with_timeout(Duration::from_secs(15));
    let options = Options {
        follow_calls: true,
        ..Options::default()
    };
    let result = engine.disassemble("program.exe", &options)?;
    for block in &result.blocks {
        for instruction in &block.instructions {
            println!("{:#x}: {}", instruction.address, instruction.text);
        }
    }
    Ok(())
}
```

`Disassembly`, `Block`, `Instruction`, and `Successor` are public, serializable
types. JSON protocol version 1 returns numeric 64-bit addresses, hex-encoded
instruction bytes, architecture, container format, entry/start addresses,
blocks, successor constraints, and diagnostics. JavaScript consumers inspecting
addresses above `2^53 - 1` should use a JSON parser that preserves large integers.
`c_next` edges are fallthrough; `c_to` edges are branch or call targets. Return
edges and a full interprocedural call graph are not reconstructed.

## Included example

`examples/sample64.exe` and `sample32.exe` are deterministic, minimal PE fixtures.
`sample.elf` contains equivalent x86-64 code. They have no imported APIs. The
entry stub loads `ECX = 5`, calls a function, and returns its result. The function
has the equivalent behavior:

```c
int example(int x) {
    if (x <= 0) return 0;
    return x + 1;
}
```

This describes the sample's bounded test input; the machine instruction uses
32-bit wrapping arithmetic for the addition. The fixtures use ECX for the
argument on every format to keep the bytes identical, not a platform C ABI on
32-bit PE or ELF. The x64 PE call stub omits normal shadow-space/alignment setup
because this leaf function does not use the stack. These are static-analysis
fixtures, not production executable templates.

Regenerate all fixtures with `python scripts/make_fixtures.py`. No compiler or
downloaded application is needed. `examples/sample64.txt`, `.json`, and `.dot`
contain output generated by the completed Rust executable.

## Tests and packaging

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
# Miasm integration tests are explicit so ordinary Cargo builds need no Python.
cargo test --test integration -- --ignored
cargo package --locked
```

Integration tests use the same `MIASM_PYTHON` selection as the CLI. See
`TESTING.md` for validation performed on this release. `cargo package` creates
`target/package/miasm-disasm-0.1.0.crate` and verifies that the archive builds.

## Local MCP server with Docker

Build a local image with the Rust CLI, Python, Miasm, and the official Python
MCP SDK bundled:

```sh
docker build -t miasm-disasm-mcp .
```

The container speaks MCP over stdio, with `doctor`, `list_files`, and
`disassemble` tools.
It opens no network port. Mount only the directory of binaries you want the
agent to inspect. Input files are analyzed statically, never executed.

IDE-specific configuration is local and is not included in this repository.
The `.vscode` directory is ignored by Git.

For other MCP-capable IDEs that use `mcpServers`, add this configuration:

```json
{
    "mcpServers": {
        "miasm-disasm": {
            "command": "/usr/local/bin/docker",
            "args": [
                "run", "--rm", "-i", "--init",
                "--network", "none", "--read-only",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "64", "--memory", "512m", "--cpus", "1",
                "--mount", "type=bind,src=/absolute/path/to/samples,dst=/samples,readonly",
                "miasm-disasm-mcp"
            ]
        }
    }
}
```

Replace `/absolute/path/to/samples` with an existing absolute directory on your
machine, such as the cloned repository's `examples` directory. Do not leave the
placeholder unchanged: Docker exits if the mount source does not exist, which
can appear in the IDE as an MCP "Connection closed" error.

Use your Docker executable's absolute path for `command`; find it with
`command -v docker` on macOS/Linux or `where.exe docker` on Windows. The example
uses a common macOS location. An absolute path avoids GUI IDEs failing to find
Docker through `PATH`.

If your configuration already has `mcpServers`, add only the `miasm-disasm`
entry inside it. Some clients use a different format, such as VS Code's
`servers` with `"type": "stdio"`; use the same command and arguments in that
client's format. Save the configuration and enable or restart the MCP server
in the IDE. Do not add `-t`: a pseudo-terminal interferes with MCP framing.
Docker Desktop or your Docker daemon must be running, and mounted files must be readable by container UID
10001. No API key, network access, or Rust/Python installation on the host is
needed after the image is built.

Ask the agent to call `doctor`, then `list_files` to discover available files.
`list_files` returns relative paths, file/directory types, and file sizes in
bytes without reading file contents. It lists one directory at a time, omits
symlinks and special files, and defaults to 100 entries (maximum 1,000).
Use `{"directory":"subfolder"}` to navigate and check `truncated` for more
entries. Returned paths can be passed directly to `disassemble`, for example
`{"file":"sample64.exe","follow_calls":true}`. File paths are relative to
`/samples`; traversal and symlinks resolving outside that directory are
rejected. The MCP tool caps requests at 120 seconds, 1,000 blocks, and 10,000
instructions. It returns structured JSON, including partial-analysis warnings.
Treat all analyzed file content as untrusted data, not agent instructions.
Container restrictions reduce exposure but do not replace a dedicated analysis
environment for hostile binaries.

Run the container's MCP protocol and path-confinement tests locally:

```sh
docker run --rm --init --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 64 --memory 512m --cpus 1 \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --mount "type=bind,src=$PWD,dst=/workspace,readonly" \
    --mount "type=bind,src=$PWD/examples,dst=/samples,readonly" \
    --workdir /workspace --entrypoint /opt/venv/bin/python \
    miasm-disasm-mcp -m unittest discover -s tests -p 'test_mcp.py' -v
```

## GitHub Actions and releases

CI builds and tests the Docker MCP server, and runs formatting, Clippy,
all Rust tests (including Miasm integration tests), and
Cargo package verification on Linux with Rust 1.85 and stable. It runs on branch
pushes and pull requests, and can also be started from the Actions tab.

To publish a GitHub release, update the version in `Cargo.toml` and the changelog,
commit and push those changes, then push a matching version tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow checks that the tag matches the Cargo version and requires
CI to pass before building binaries for Linux x86-64 (glibc 2.35 or newer),
macOS Apple Silicon, and Windows x86-64. It publishes `.tar.gz` binary archives,
a verified `.crate` source archive, and `SHA256SUMS` with generated release notes.
Tags containing a hyphen, such as `v0.2.0-rc.1`, produce prereleases. This does
not publish to crates.io. No additional repository secrets are required; the
publishing job uses GitHub's built-in token with `contents: write` permission.

For a binary release, extract the archive and install `python/requirements.txt`
in a virtual environment using the commands above, skipping `cargo install`.
Set `MIASM_PYTHON` to that environment's interpreter and run the extracted
`miasm-disasm` executable (or `miasm-disasm.exe` on Windows). Python and Miasm are
not bundled. To verify downloads on Linux, run `sha256sum --check SHA256SUMS`
with all release assets in the same directory; macOS provides
`shasum -a 256 --check SHA256SUMS`.

## Upstream and license

Miasm project: https://github.com/cea-sec/miasm  
Miasm examples and explanations: https://miasm.re/blog/

This package is GPL-2.0-only. Miasm is a separately installed GPL-2.0-only
dependency; its source is not vendored into this archive. See `LICENSE` and
`NOTICE`. This package is an independent integration, not an official Miasm
release.
