use itm::{Decoder, DecoderError, DecoderOptions};
use std::fs::File;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(
    about = "An ITM/DWT packet protocol decoder, as specified in the ARMv7-M architecture reference manual, Appendix D4. See <https://developer.arm.com/documentation/ddi0403/ed/>. Report bugs and request features at <https://github.com/rust-embedded/itm>."
)]
struct Opt {
    #[structopt(long = "--ignore-eof")]
    ignore_eof: bool,

    #[structopt(name = "FILE", parse(from_os_str), help = "Raw trace input file.")]
    file: PathBuf,
}

fn main() -> Result<(), DecoderError> {
    let opt = Opt::from_args();

    let file = File::open(opt.file)?;
    let mut decoder = Decoder::<File>::new(
        file,
        DecoderOptions {
            ignore_eof: opt.ignore_eof,
        },
    );
    let mut it = decoder.singles();

    loop {
        match it.next() {
            None => return Ok(()), // EOF
            Some(Err(e)) => return Err(e),
            Some(Ok(packet)) => println!("{:?}", packet),
        }
    }
}
