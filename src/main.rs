use clap::{Parser, Subcommand, ValueEnum};
use miasm_disasm::{Disassembler, Mode, Options};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

#[derive(Parser)]
#[command(
    version,
    about = "Static PE/ELF/raw disassembly using the Miasm framework"
)]
struct Cli {
    /// Python interpreter containing Miasm (prefer a virtual environment)
    #[arg(long, global = true, env = "MIASM_PYTHON")]
    python: Option<PathBuf>,
    /// Worker timeout in seconds
    #[arg(long, global = true, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
    timeout: u64,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Check the Python/Miasm installation and list architecture names
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Disassemble a file without running it
    Disasm {
        file: PathBuf,
        /// Miasm architecture, e.g. x86_32, x86_64, arml, aarch64l
        #[arg(long)]
        arch: Option<String>,
        /// Treat the file as raw machine code (requires --arch)
        #[arg(long, requires = "arch")]
        raw: bool,
        /// Raw image base address, decimal or 0x-prefixed hexadecimal
        #[arg(long, requires = "raw", value_parser = parse_address)]
        base: Option<u64>,
        /// Virtual start address, decimal or 0x-prefixed hexadecimal
        #[arg(long, value_parser = parse_address)]
        start: Option<u64>,
        #[arg(long, value_enum, default_value_t = ScanMode::Cfg)]
        mode: ScanMode,
        /// Follow direct call destinations in CFG mode
        #[arg(long)]
        follow_calls: bool,
        #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..=10000))]
        max_blocks: u32,
        #[arg(long, default_value_t = 10000, value_parser = clap::value_parser!(u32).range(1..=100000))]
        max_instructions: u32,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Write a new output file; refuses to overwrite an existing file
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Return exit code 3 for limit/decode warnings, after writing the result
        #[arg(long)]
        fail_on_partial: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ScanMode {
    Cfg,
    Linear,
}
#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Dot,
}

fn parse_address(value: &str) -> Result<u64, String> {
    let value = value.replace('_', "");
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|_| "expected an unsigned decimal or 0x-prefixed address".into())
}

fn write_output(output: Option<PathBuf>, content: &str) -> io::Result<()> {
    if let Some(path) = output {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?
            .write_all(content.as_bytes())
    } else {
        io::stdout().lock().write_all(content.as_bytes())
    }
}

fn run(cli: Cli) -> Result<u8, Box<dyn std::error::Error>> {
    let engine = cli
        .python
        .map(Disassembler::new)
        .unwrap_or_default()
        .with_timeout(Duration::from_secs(cli.timeout));
    match cli.command {
        Action::Doctor { json } => {
            let status = engine.doctor()?;
            let content = if json {
                format!("{}\n", serde_json::to_string_pretty(&status)?)
            } else {
                format!(
                    "Python {} | Miasm {}\nArchitectures: {}\n",
                    status.python_version,
                    status.miasm_version,
                    status.architectures.join(", ")
                )
            };
            write_output(None, &content)?;
            Ok(0)
        }
        Action::Disasm {
            file,
            arch,
            raw,
            base,
            start,
            mode,
            follow_calls,
            max_blocks,
            max_instructions,
            format,
            output,
            fail_on_partial,
        } => {
            let options = Options {
                arch,
                raw,
                base: base.unwrap_or(0),
                start,
                mode: match mode {
                    ScanMode::Cfg => Mode::Cfg,
                    ScanMode::Linear => Mode::Linear,
                },
                follow_calls,
                max_blocks,
                max_instructions,
            };
            let result = engine.disassemble(file, &options)?;
            let content = match format {
                OutputFormat::Text => result.to_text(),
                OutputFormat::Json => format!("{}\n", serde_json::to_string_pretty(&result)?),
                OutputFormat::Dot => result.to_dot(),
            };
            write_output(output, &content)?;
            Ok(if fail_on_partial && result.is_partial() {
                3
            } else {
                0
            })
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
            {
                return ExitCode::SUCCESS;
            }
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_hex_and_full_width_addresses() {
        assert_eq!(parse_address("0x1400_01000"), Ok(0x140001000));
        assert_eq!(parse_address("42"), Ok(42));
        assert_eq!(parse_address("0Xffffffffffffffff"), Ok(u64::MAX));
        assert!(parse_address("-1").is_err());
        assert!(parse_address("0x10000000000000000").is_err());
    }

    #[test]
    fn raw_requires_arch_and_base_requires_raw() {
        assert!(Cli::try_parse_from(["miasm-disasm", "disasm", "x", "--raw"]).is_err());
        assert!(Cli::try_parse_from(["miasm-disasm", "disasm", "x", "--base", "4096"]).is_err());
    }
}
