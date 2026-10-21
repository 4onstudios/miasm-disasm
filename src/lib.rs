//! Static disassembly through Miasm, exposed as a typed Rust API.
//!
//! Install the pinned Python requirements first. Each request starts an isolated
//! Python worker. No CPython development headers or embedded interpreter are needed.
//!
//! ```no_run
//! use miasm_disasm::{Disassembler, Options};
//! let engine = Disassembler::new(".venv/bin/python");
//! let result = engine.disassemble("program.exe", &Options::default())?;
//! println!("{}", result.to_text());
//! # Ok::<(), miasm_disasm::Error>(())
//! ```

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fmt,
    fmt::Write as _,
    io::{self, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const BRIDGE: &str = include_str!("../python/bridge.py");
const MAX_CAPTURE: usize = 64 * 1024 * 1024;

/// Failure to validate input, launch Python, or decode a binary.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidOptions(String),
    PythonNotFound(OsString),
    Timeout(Duration),
    Backend { code: String, message: String },
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::InvalidOptions(e) => write!(f, "invalid options: {e}"),
            Self::PythonNotFound(p) => write!(
                f,
                "cannot find Python interpreter {}; pass --python PATH",
                p.to_string_lossy()
            ),
            Self::Timeout(d) => write!(
                f,
                "Miasm worker exceeded the {} second timeout",
                d.as_secs_f64()
            ),
            Self::Backend { code, message } => write!(f, "{code}: {message}"),
            Self::Protocol(e) => write!(f, "invalid Miasm bridge response: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// CFG traversal follows statically known branches. Linear mode scans consecutive bytes.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Cfg,
    Linear,
}

/// Analysis options. Addresses are virtual addresses, not file offsets.
#[derive(Debug, Clone, Serialize)]
pub struct Options {
    /// Miasm architecture name, e.g. `x86_64` or `aarch64l`. Required for raw input.
    pub arch: Option<String>,
    pub raw: bool,
    /// Load address of raw bytes; must be zero for PE/ELF inputs.
    pub base: u64,
    /// Start address. Defaults to executable entry point or the raw base address.
    pub start: Option<u64>,
    pub mode: Mode,
    /// Follow direct calls as well as branches. Indirect calls are not resolved.
    pub follow_calls: bool,
    /// Maximum decoded blocks before Miasm splits overlapping blocks.
    pub max_blocks: u32,
    /// Maximum instructions; a limit produces a flagged partial result.
    pub max_instructions: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            arch: None,
            raw: false,
            base: 0,
            start: None,
            mode: Mode::Cfg,
            follow_calls: false,
            max_blocks: 256,
            max_instructions: 10_000,
        }
    }
}

impl Options {
    pub fn raw(architecture: impl Into<String>, base: u64) -> Self {
        Self {
            arch: Some(architecture.into()),
            raw: true,
            base,
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<(), Error> {
        let problem = if self.raw && self.arch.as_deref().unwrap_or("").is_empty() {
            Some("raw input requires an architecture")
        } else if !self.raw && self.base != 0 {
            Some("base is only valid for raw input")
        } else if !(1..=10_000).contains(&self.max_blocks) {
            Some("max_blocks must be between 1 and 10000")
        } else if !(1..=100_000).contains(&self.max_instructions) {
            Some("max_instructions must be between 1 and 100000")
        } else {
            None
        };
        match problem {
            Some(p) => Err(Error::InvalidOptions(p.into())),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub size: u32,
    /// Lowercase, contiguous hexadecimal bytes.
    pub bytes: String,
    pub mnemonic: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Successor {
    pub address: u64,
    /// Miasm constraint: `c_next` (fallthrough) or `c_to` (branch/call target).
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub address: u64,
    pub label: String,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<Successor>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disassembly {
    pub protocol: u32,
    pub miasm_version: String,
    pub format: String,
    pub architecture: String,
    pub mode: Mode,
    pub entry_point: u64,
    pub start_address: u64,
    pub truncated: bool,
    pub instruction_count: usize,
    pub blocks: Vec<Block>,
    pub warnings: Vec<String>,
}

fn visible(text: &str) -> String {
    // Input-controlled symbol names must not emit terminal escape sequences.
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

impl Disassembly {
    /// Whether a limit or decode warning requires reviewing partial output.
    pub fn is_partial(&self) -> bool {
        self.truncated || !self.warnings.is_empty()
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} | {} | {:?} | entry {:#x} | start {:#x}",
            self.format, self.architecture, self.mode, self.entry_point, self.start_address
        );
        let _ = writeln!(
            out,
            "{} instructions, {} blocks{}",
            self.instruction_count,
            self.blocks.len(),
            if self.truncated {
                " (limit reached)"
            } else {
                ""
            }
        );
        for block in &self.blocks {
            let _ = writeln!(out, "\n{}:", visible(&block.label));
            for item in &block.instructions {
                let _ = writeln!(
                    out,
                    "  {:016x}  {:<30}  {}",
                    item.address,
                    item.bytes,
                    visible(&item.text)
                );
            }
            if let Some(error) = &block.error {
                let _ = writeln!(out, "  ! {}", visible(error));
            }
            for edge in &block.successors {
                let _ = writeln!(out, "  -> {:#x} ({})", edge.address, visible(&edge.kind));
            }
        }
        for warning in &self.warnings {
            let _ = writeln!(out, "warning: {}", visible(warning));
        }
        out
    }

    /// Graphviz DOT. Unknown destinations are emitted as dashed nodes.
    pub fn to_dot(&self) -> String {
        fn escape(value: &str) -> String {
            visible(value).replace('\\', "\\\\").replace('"', "\\\"")
        }
        let mut out =
            String::from("digraph disassembly {\n  node [shape=box, fontname=\"monospace\"];\n");
        let known: BTreeSet<_> = self.blocks.iter().map(|b| b.address).collect();
        for warning in &self.warnings {
            let _ = writeln!(out, "  // warning: {}", visible(warning));
        }
        for block in &self.blocks {
            let mut label = format!("{:#x}\\l", block.address);
            for item in &block.instructions {
                let _ = write!(label, "{:x}: {}\\l", item.address, escape(&item.text));
            }
            if let Some(error) = &block.error {
                let _ = write!(label, "{}\\l", escape(error));
            }
            let _ = writeln!(out, "  n{:x} [label=\"{}\"];", block.address, label);
            for edge in &block.successors {
                if !known.contains(&edge.address) {
                    let _ = writeln!(
                        out,
                        "  n{:x} [label=\"{:#x} (not decoded)\", style=dashed];",
                        edge.address, edge.address
                    );
                }
                let _ = writeln!(
                    out,
                    "  n{:x} -> n{:x} [label=\"{}\"];",
                    block.address,
                    edge.address,
                    escape(&edge.kind)
                );
            }
        }
        out.push_str("}\n");
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Doctor {
    pub protocol: u32,
    pub python_version: String,
    pub miasm_version: String,
    /// Architecture names advertised by this Miasm version.
    pub architectures: Vec<String>,
}

/// Configuration for independent, time-bounded Miasm subprocesses.
#[derive(Debug, Clone)]
pub struct Disassembler {
    python: OsString,
    timeout: Duration,
}

impl Default for Disassembler {
    fn default() -> Self {
        Self::new(std::env::var_os("MIASM_PYTHON").unwrap_or_else(|| {
            if cfg!(windows) {
                "python".into()
            } else {
                "python3".into()
            }
        }))
    }
}

impl Disassembler {
    pub fn new(python: impl AsRef<OsStr>) -> Self {
        Self {
            python: python.as_ref().to_owned(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn doctor(&self) -> Result<Doctor, Error> {
        self.request(serde_json::json!({ "protocol": 1, "operation": "doctor" }))
    }

    pub fn disassemble(
        &self,
        path: impl AsRef<Path>,
        options: &Options,
    ) -> Result<Disassembly, Error> {
        options.validate()?;
        let path = path.as_ref().canonicalize()?;
        if !path.is_file() {
            return Err(Error::InvalidOptions("input must be a regular file".into()));
        }
        let path = path
            .to_str()
            .ok_or_else(|| Error::InvalidOptions("input path must be valid Unicode".into()))?;
        let mut request =
            serde_json::to_value(options).map_err(|e| Error::Protocol(e.to_string()))?;
        request["protocol"] = 1.into();
        request["operation"] = "disassemble".into();
        request["path"] = path.into();
        self.request(request)
    }

    fn request<T: DeserializeOwned>(&self, request: serde_json::Value) -> Result<T, Error> {
        if self.timeout.is_zero() {
            return Err(Error::InvalidOptions(
                "timeout must be greater than zero".into(),
            ));
        }
        let bytes = serde_json::to_vec(&request).map_err(|e| Error::Protocol(e.to_string()))?;
        let child = Command::new(&self.python)
            .args(["-I", "-c", BRIDGE])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    Error::PythonNotFound(self.python.clone())
                } else {
                    Error::Io(e)
                }
            })?;
        let mut guard = ChildGuard(child);
        let stdout = guard.0.stdout.take().expect("piped stdout");
        let stderr = guard.0.stderr.take().expect("piped stderr");
        let out_reader = thread::spawn(move || read_bounded(stdout));
        let err_reader = thread::spawn(move || read_bounded(stderr));
        let start = Instant::now();
        let mut stdin = guard.0.stdin.take().expect("piped stdin");
        // Write in a thread so a non-responsive interpreter cannot block timeout handling.
        let input_writer = thread::spawn(move || stdin.write_all(&bytes));
        let status = loop {
            if let Some(status) = guard.0.try_wait()? {
                break status;
            }
            if start.elapsed() >= self.timeout {
                let _ = guard.0.kill();
                let _ = guard.0.wait();
                let _ = input_writer.join();
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err(Error::Timeout(self.timeout));
            }
            thread::sleep(Duration::from_millis(10));
        };
        let input_result = input_writer
            .join()
            .map_err(|_| Error::Protocol("stdin writer panicked".into()))?;
        let stdout = out_reader
            .join()
            .map_err(|_| Error::Protocol("stdout reader panicked".into()))??;
        let stderr = err_reader
            .join()
            .map_err(|_| Error::Protocol("stderr reader panicked".into()))??;
        if !status.success() {
            return Err(Error::Backend {
                code: "process_failed".into(),
                message: format!(
                    "Python exited with {status}: {}",
                    visible(&String::from_utf8_lossy(&stderr))
                ),
            });
        }
        input_result?;
        let response: serde_json::Value = serde_json::from_slice(&stdout).map_err(|e| {
            Error::Protocol(format!(
                "{e}; stderr: {}",
                visible(&String::from_utf8_lossy(&stderr))
            ))
        })?;
        if response["ok"] == false {
            return Err(Error::Backend {
                code: response["error"]["code"]
                    .as_str()
                    .unwrap_or("backend_error")
                    .to_string(),
                message: response["error"]["message"]
                    .as_str()
                    .unwrap_or("unspecified backend failure")
                    .to_string(),
            });
        }
        if response["ok"] != true || response["result"]["protocol"] != 1 {
            return Err(Error::Protocol(
                "missing success marker or unsupported protocol".into(),
            ));
        }
        serde_json::from_value(response["result"].clone())
            .map_err(|e| Error::Protocol(e.to_string()))
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn read_bounded(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = [0; 8192];
    let mut exceeded = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if out.len() + count <= MAX_CAPTURE && !exceeded {
            out.extend_from_slice(&buffer[..count]);
        } else {
            exceeded = true;
        } // Drain the pipe even after reaching the cap.
    }
    if exceeded {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "worker output exceeded 64 MiB",
        ))
    } else {
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_options_are_rejected_before_launch() {
        let invalid = Options {
            max_instructions: 0,
            ..Options::default()
        };
        assert!(matches!(
            Disassembler::new("missing-interpreter").disassemble("none", &invalid),
            Err(Error::InvalidOptions(_))
        ));
    }

    #[test]
    fn missing_interpreter_is_actionable() {
        assert!(matches!(
            Disassembler::new("/nonexistent-miasm-python").doctor(),
            Err(Error::PythonNotFound(_))
        ));
    }

    #[test]
    fn zero_timeout_is_rejected() {
        assert!(matches!(
            Disassembler::default()
                .with_timeout(Duration::ZERO)
                .doctor(),
            Err(Error::InvalidOptions(_))
        ));
    }

    #[test]
    fn terminal_controls_are_escaped() {
        assert_eq!(visible("symbol\x1b[31m\n"), "symbol\\u{1b}[31m\\n");
    }
}
