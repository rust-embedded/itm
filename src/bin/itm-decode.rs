use anyhow::{Context, Result};
use itm_decode::{Decoder, DecoderState, TracePacket};
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

    if opt.naive {
        eprintln!("This decoder is naive: any decode errors are presumed trivial (next byte in bitstream presumed to be a new header).\n");
    }

    loop {
        match decoder.pull() {
            Ok(Some(TracePacket::Instrumentation {
                port: _,
                payload: _,
            })) if opt.instr_as_string => {
                todo!();
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

    Ok(())
}
