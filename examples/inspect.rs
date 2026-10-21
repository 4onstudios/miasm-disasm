use miasm_disasm::{Disassembler, Options};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("usage: inspect FILE")?;
    let options = Options {
        follow_calls: true,
        ..Options::default()
    };
    let result = Disassembler::default().disassemble(path, &options)?;
    println!("{}", result.to_text());
    Ok(())
}
