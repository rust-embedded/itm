use anyhow::{bail, Context, Result};
use itm::{chrono, Decoder, DecoderOptions, LocalTimestampOptions, TimestampsConfiguration};
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

    #[structopt(long = "--timestamps", requires("freq"))]
    timestamps: bool,

    #[structopt(long = "--itm-prescaler")]
    prescaler: Option<u8>,

    #[structopt(long = "--itm-freq", name = "freq")]
    freq: u32,

    #[structopt(long = "--expect-malformed")]
    expect_malformed: bool,

    #[structopt(name = "FILE", parse(from_os_str), help = "Raw trace input file.")]
    file: PathBuf,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    let file = File::open(opt.file).context("failed to open file")?;
    let mut decoder = Decoder::<File>::new(
        file,
        DecoderOptions {
            ignore_eof: opt.ignore_eof,
        },
    );

    if opt.timestamps {
        let mut it = decoder.timestamps(TimestampsConfiguration {
            clock_frequency: opt.freq,
            lts_prescaler: match opt.prescaler {
                None | Some(1) => LocalTimestampOptions::Enabled,
                Some(4) => LocalTimestampOptions::EnabledDiv4,
                Some(16) => LocalTimestampOptions::EnabledDiv16,
                Some(64) => LocalTimestampOptions::EnabledDiv64,
                Some(n) => bail!(
                    "{} is not a valid prescaler; valid prescalers are: 4, 16, 64.",
                    n
                ),
            },
            baseline: chrono::offset::Utc::now(),
            expect_malformed: opt.expect_malformed,
        });

        loop {
            match it.next() {
                None => return Ok(()), // EOF
                Some(Err(e)) => return Err(e).context("Decoder error"),
                Some(Ok(packets)) => println!("{:?}", packets),
            }
        }
    } else {
        let mut it = decoder.singles();

        loop {
            match it.next() {
                None => return Ok(()), // EOF
                Some(Err(e)) => return Err(e).context("Decoder error"),
                Some(Ok(packet)) => println!("{:?}", packet),
            }
        }
    }
}
