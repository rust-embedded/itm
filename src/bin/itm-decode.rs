use anyhow::{Context, Result};
use itm_decode::{Decoder, DecoderState, TracePacket};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(
    about = "An ITM/DWT packet protocol decoder, as specified in the ARMv7-M architecture reference manual, Appendix D4. See <https://developer.arm.com/documentation/ddi0403/ed/>. Report bugs and request features at <https://github.com/tmplt/itm-decode>."
)]
struct Opt {
    #[structopt(
        short,
        long,
        help = "Presume decode errors are trivially resolved (effectivly assumes the next byte in the bitstream after anerror is a new header)"
    )]
    naive: bool,

    #[structopt(
        short = "-s",
        long = "--stimulus-strings",
        help = "Decode instumentation packets as UTF-8 strings (assumes each string ends with a newline)"
    )]
    instr_as_string: bool,

    #[structopt(name = "FILE", parse(from_os_str))]
    file: PathBuf,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    // Read the whole file and feed to decoder
    let mut decoder = {
        let mut f = File::open(opt.file.clone())
            .with_context(|| format!("Failed to open {:?}", opt.file))?;
        let mut buf: Vec<u8> = Vec::new();
        f.read_to_end(&mut buf)
            .with_context(|| format!("Failed to buffer {:?}", opt.file))?;
        let mut decoder = Decoder::new();
        decoder.feed(buf);

        decoder
    };

    let mut stim = BTreeMap::new();

    loop {
        match decoder.pull() {
            Ok(Some(TracePacket::Instrumentation { port, payload })) if opt.instr_as_string => {
                // lossily convert payload to UTF-8 string
                if !stim.contains_key(&port) {
                    stim.insert(port, String::new());
                }
                let string = stim.get_mut(&port).unwrap();
                string.push_str(&String::from_utf8_lossy(&payload));

                // If a newline is encountered, the user likely wants
                // the string to be printed.
                if let Some(c) = string.chars().last() {
                    if c == '\n' {
                        for line in string.lines() {
                            println!("port {}> {}", port, line);
                        }

                        string.clear();
                    }
                }
            }
            Ok(Some(packet)) => println!("{:?}", packet),
            Ok(None) => break,

            Err(e) if !opt.naive => {
                println!("Error: {:?}", e);
                break;
            }
            Err(e) if opt.naive => {
                println!("Error: {:?}", e);
                decoder.state = DecoderState::Header;
            }
            _ => unreachable!(),
        }
    }

    if stim.iter().any(|(_, string)| !string.is_empty()) {
        println!("Warning: decoded incomplete UTF-8 strings from instrumentation packets:");
    }
    for (port, string) in stim {
        for line in string.lines() {
            println!("port {}> {}", port, line);
        }
    }

    Ok(())
}
