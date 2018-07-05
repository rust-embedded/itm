#![deny(warnings)]

extern crate chrono;
extern crate clap;
extern crate env_logger;
extern crate failure;
extern crate itm;
#[macro_use]
extern crate log;

use clap::{App, Arg, ArgMatches};
use itm::{packet, Decoder, Error};
use log::{LogLevelFilter, LogRecord};
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use std::{env, io, process, thread};

fn main() {
    // Initialise logging.
    env_logger::LogBuilder::new()
        .format(|r: &LogRecord| {
            format!("\n{time} {lvl} {mod} @{file}:{line}\n  {args}",
                time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f_UTC"),
                lvl = r.level(),
                mod = r.location().module_path(),
                file = r.location().file(),
                line = r.location().line(),
                args = r.args())
        })
        .filter(None, LogLevelFilter::Info)
        .parse(&env::var("RUST_LOG").unwrap_or(String::from("")))
        .init()
        .unwrap();

    if let Err(e) = run() {
        eprintln!("{}", e);

        process::exit(1)
    }
}

fn run() -> Result<(), failure::Error> {
    let matches = App::new("itmdump")
        .version(concat!(
            env!("CARGO_PKG_VERSION"),
            include_str!(concat!(env!("OUT_DIR"), "/commit-info.txt"))
        ))
        .about(
            "\n\
             Reads data from an ARM CPU ITM and decodes it. \n\
             \n\
             Input is from an existing file (or named pipe) at a \
             supplied path, or else from standard input.",
        )
        .arg(
            Arg::with_name("file")
                .long("file")
                .short("f")
                .help("Path to file (or named pipe) to read from")
                .takes_value(true),
        )
        .arg(Arg::with_name("follow").long("follow").short("F").help(
            "Keep the file open after reading through it and \
             append new output as it is written. Like `tail -f'.",
        ))
        .arg(
            Arg::with_name("port")
                .long("stimulus")
                .short("s")
                .help("Stimulus port to extract ITM data for.")
                .takes_value(true)
                .default_value("0")
                .validator(|s| match s.parse::<u8>() {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.to_string()),
                }),
        )
        .get_matches();

    let port = matches.value_of("port")
                           .unwrap() // We supplied a default value
                           .parse::<u8>()
                           .expect("Arg validator should ensure this parses");

    let follow = matches.is_present("follow");

    let read = open_read(&matches)?;
    let mut decoder = Decoder::new(read, follow);

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    loop {
        let p = decoder.read_packet();
        match p {
            Ok(p) => match p.kind() {
                &packet::Kind::Instrumentation(ref i) if i.port() == port => {
                    stdout.write_all(&i.payload())?;
                    stdout.flush()?;
                }
                _ => (),
            },
            Err(fe) => {
                if let Some(ie) = fe.downcast_ref::<Error>().cloned() {
                    match ie {
                        Error::UnknownHeader { byte } => {
                            // We don't know this header type; warn and continue.
                            debug!("unknown header byte: {:x}", byte);
                        }
                        Error::EofBeforePacket => {
                            if follow {
                                // NOTE 10 ms let us achieve 60 FPS in the worst case scenario
                                thread::sleep(Duration::from_millis(10));
                            } else {
                                // !follow and EOF. Exit.
                                return Ok(());
                            }
                        }
                        _ => return Err(fe.into()),
                    }
                } else {
                    return Err(fe);
                }
            }
        }
    } // end of read loop

    // Unreachable.
}

fn open_read(matches: &ArgMatches) -> Result<Box<io::Read + 'static>, io::Error> {
    let path = matches.value_of("file");
    Ok(match path {
        Some(path) => {
            let f = File::open(path)?;
            Box::new(f) as Box<io::Read + 'static>
        }
        None => Box::new(io::stdin()) as Box<io::Read + 'static>,
    })
}
