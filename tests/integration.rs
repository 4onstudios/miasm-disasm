//! Run with MIASM_PYTHON pointing at the installed environment:
//! cargo test --test integration -- --ignored
use miasm_disasm::{Disassembler, Error, Mode, Options};
use std::{fs, path::PathBuf, process::Command, time::Duration};

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("miasm-disasm-{}-{label}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn recognizes_pe32_pe64_and_elf_virtual_addresses() {
    for (name, fmt, arch, entry) in [
        ("sample32.exe", "PE", "x86_32", 0x401000),
        ("sample64.exe", "PE", "x86_64", 0x140001000),
        ("sample.elf", "ELF", "x86_64", 0x401000),
    ] {
        let result = Disassembler::default()
            .disassemble(fixture(name), &Options::default())
            .unwrap();
        assert_eq!(
            (
                result.format.as_str(),
                result.architecture.as_str(),
                result.entry_point
            ),
            (fmt, arch, entry)
        );
        assert_eq!(result.blocks[0].instructions[0].bytes, "b905000000");
        assert_eq!(result.instruction_count, 3);
        assert!(!result.is_partial(), "{name}: {:?}", result.warnings);
    }
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn follows_calls_and_both_sides_of_a_branch() {
    let options = Options {
        follow_calls: true,
        ..Options::default()
    };
    let result = Disassembler::default()
        .disassemble(fixture("sample64.exe"), &options)
        .unwrap();
    assert_eq!(result.blocks.len(), 5);
    assert_eq!(result.instruction_count, 9);
    let branch = result
        .blocks
        .iter()
        .find(|b| b.address == 0x140001010)
        .unwrap();
    assert_eq!(
        branch
            .successors
            .iter()
            .map(|s| s.address)
            .collect::<Vec<_>>(),
        [0x140001014, 0x140001018]
    );
    assert!(result.to_dot().contains("n140001010 -> n140001018"));
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn raw_base_and_start_are_virtual_addresses() {
    let mut options = Options::raw("x86_64", 0x9000);
    let result = Disassembler::default()
        .disassemble(fixture("branch.bin"), &options)
        .unwrap();
    assert_eq!(result.entry_point, 0x9000);
    assert_eq!(result.blocks.len(), 3);
    options.start = Some(0x9008);
    let result = Disassembler::default()
        .disassemble(fixture("branch.bin"), &options)
        .unwrap();
    assert_eq!(result.instruction_count, 2);
    assert_eq!(result.blocks[0].instructions[0].mnemonic, "XOR");
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn instruction_and_block_limits_are_reported_without_overrun() {
    for options in [
        Options {
            max_instructions: 2,
            ..Options::raw("x86_64", 0)
        },
        Options {
            max_blocks: 1,
            ..Options::raw("x86_64", 0)
        },
    ] {
        let result = Disassembler::default()
            .disassemble(fixture("branch.bin"), &options)
            .unwrap();
        assert!(result.truncated);
        assert!(result.instruction_count <= 2);
    }
    let options = Options {
        max_instructions: 1,
        start: Some(7),
        ..Options::raw("x86_64", 0)
    };
    let result = Disassembler::default()
        .disassemble(fixture("branch.bin"), &options)
        .unwrap();
    assert_eq!(result.blocks[0].instructions[0].mnemonic, "RET");
    assert!(
        !result.truncated,
        "an exact terminal limit should be complete"
    );
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn linear_scan_and_aarch64_decode() {
    let options = Options {
        mode: Mode::Linear,
        ..Options::raw("aarch64l", 0x8000)
    };
    let result = Disassembler::default()
        .disassemble(fixture("aarch64.bin"), &options)
        .unwrap();
    assert_eq!(result.instruction_count, 2);
    assert_eq!(result.blocks[0].instructions[0].mnemonic, "ADD");
    assert_eq!(result.blocks[0].instructions[1].mnemonic, "RET");
    assert!(!result.truncated);
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn backward_branch_splits_existing_block_without_duplicate_instructions() {
    let result = Disassembler::default()
        .disassemble(fixture("overlap.bin"), &Options::raw("x86_64", 0))
        .unwrap();
    let mut addresses: Vec<_> = result
        .blocks
        .iter()
        .flat_map(|b| b.instructions.iter().map(|i| i.address))
        .collect();
    addresses.sort();
    assert_eq!(addresses, [0, 1, 2, 4]);
    assert_eq!(result.blocks.len(), 3);
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn errors_for_unknown_format_and_unmapped_start() {
    let error = Disassembler::default()
        .disassemble(fixture("branch.bin"), &Options::default())
        .unwrap_err();
    assert!(matches!(error, Error::Backend { code, .. } if code == "unsupported_format"));
    let options = Options {
        start: Some(0xdeadbeef),
        ..Options::default()
    };
    let error = Disassembler::default()
        .disassemble(fixture("sample64.exe"), &options)
        .unwrap_err();
    assert!(matches!(error, Error::Backend { code, .. } if code == "decode_error"));
}

#[test]
#[ignore = "requires a Python interpreter"]
fn wall_clock_timeout_kills_worker() {
    let error = Disassembler::default()
        .with_timeout(Duration::from_nanos(1))
        .doctor()
        .unwrap_err();
    assert!(matches!(error, Error::Timeout(_)));
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn malformed_pe_is_rejected_without_raw_fallback() {
    let scratch = Scratch::new("malformed");
    let path = scratch.0.join("broken.exe");
    fs::write(&path, b"MZthis is not a PE header").unwrap();
    let error = Disassembler::default()
        .disassemble(path, &Options::default())
        .unwrap_err();
    assert!(matches!(error, Error::Backend { code, .. } if code == "invalid_binary"));
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn filenames_with_spaces_and_unicode_are_passed_as_data() {
    let scratch = Scratch::new("filenames");
    let path = scratch.0.join("sample code λ & data.exe");
    fs::copy(fixture("sample64.exe"), &path).unwrap();
    let result = Disassembler::default()
        .disassemble(path, &Options::default())
        .unwrap();
    assert_eq!(result.instruction_count, 3);
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn cli_json_and_partial_exit_code() {
    let output = Command::new(env!("CARGO_BIN_EXE_miasm-disasm"))
        .arg("disasm")
        .arg(fixture("sample64.exe"))
        .args([
            "--max-instructions",
            "1",
            "--format",
            "json",
            "--fail-on-partial",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["truncated"], true);
    assert_eq!(result["instruction_count"], 1);
}

#[test]
#[ignore = "requires the pinned Miasm Python environment"]
fn cli_output_refuses_to_overwrite_existing_file() {
    let scratch = Scratch::new("overwrite");
    let output_path = scratch.0.join("keep.txt");
    fs::write(&output_path, "preserve this").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_miasm-disasm"))
        .arg("disasm")
        .arg(fixture("sample64.exe"))
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read_to_string(output_path).unwrap(), "preserve this");
}
