use anyhow::{anyhow, Context, Result};
use itm_decode::{Decoder, DecoderState};
use std::env;
use std::fs::File;
use std::io::Read;

fn help(args: Vec<String>) {
    eprintln!("AN ITM/DWT packet protocol decoder, as specified in the ARMv7-M architecture reference manual, Appendix D4.");
    eprintln!("See <https://developer.arm.com/documentation/ddi0403/ed/>");
    eprintln!("usage: {} <trace-file>", args[0]);
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.contains(&String::from("-h")) || args.contains(&String::from("--help")) {
        help(args);
        return Ok(());
    }

    match args.len() {
        2 => {
            // Read the whole file
            let mut f = File::open(args[1].clone())
                .with_context(|| format!("Failed to open {}", args[1]))?;
            let mut buf: Vec<u8> = Vec::new();
            f.read_to_end(&mut buf)
                .with_context(|| format!("Failed to buffer {}", args[1]))?;

            let mut decoder = Decoder::new();
            decoder.feed(buf);

            eprintln!("This decoder is naive: any decode errors are presumed trivial (next byte in bitstream presumed to be a new header).\n");

            loop {
                match decoder.pull() {
                    Ok(Some(packet)) => println!("{:?}", packet),
                    Ok(None) => break,
                    Err(e) => {
                        println!("Error: {:?}", e);
                        decoder.state = DecoderState::Header;
                    }
                }
            }

            Ok(())
        }
        _ => {
            help(args);
            Err(anyhow!("Invalid number of arguments"))
        }
    }
}
