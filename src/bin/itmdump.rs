extern crate chrono;
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate libc;
#[macro_use]
extern crate log;
extern crate ref_slice;

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;
use std::{env, fs, io, process, thread};

#[cfg(not(unix))]
use std::fs::OpenOptions;

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use clap::{App, Arg};
use log::{LogRecord, LogLevelFilter};
use ref_slice::ref_slice_mut;

use errors::*;

mod errors {
    error_chain!();
}

fn main() {
    // Initialise logging.
    env_logger::LogBuilder::new()
        .format(|r: &LogRecord|
            format!("\n{time} {lvl} {mod} @{file}:{line}\n  {args}",
                time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f_UTC"),
                lvl = r.level(),
                mod = r.location().module_path(),
                file = r.location().file(),
                line = r.location().line(),
                args = r.args())
        )
        .filter(None, LogLevelFilter::Info)
        .parse(&env::var("RUST_LOG").unwrap_or(String::from("")))
        .init().unwrap();

    fn show_backtrace() -> bool {
        env::var("RUST_BACKTRACE").as_ref().map(|s| &s[..]) == Ok("1")
    }

    if let Err(e) = run() {
        let stderr = io::stderr();
        let mut stderr = stderr.lock();

        writeln!(stderr, "{}", e).unwrap();

        for e in e.iter().skip(1) {
            writeln!(stderr, "caused by: {}", e).unwrap();
        }

        if show_backtrace() {
            if let Some(backtrace) = e.backtrace() {
                writeln!(stderr, "{:?}", backtrace).unwrap();
            }
        }

        process::exit(1)
    }
}

fn run() -> Result<()> {
    let matches = App::new("itmdump")
        .version(include_str!(concat!(env!("OUT_DIR"), "/commit-info.txt")))
        .arg(Arg::with_name("PATH").help("Named pipe to use").required(true))
        .get_matches();

    let pipe = PathBuf::from(matches.value_of("PATH").unwrap());
    let pipe_ = pipe.display();

    if pipe.exists() {
        try!(fs::remove_file(&pipe)
            .chain_err(|| format!("couldn't remove {}", pipe_)));
    }

    let mut stream = match () {
        #[cfg(unix)]
        () => {
            let cpipe =
                try!(CString::new(pipe.clone().into_os_string().into_vec())
                     .chain_err(|| {
                         format!("error converting {} to a C string", pipe_)
                     }));

            match unsafe { libc::mkfifo(cpipe.as_ptr(), 0o644) } {
                0 => {}
                e => {
                    try!(Err(io::Error::from_raw_os_error(e)).chain_err(|| {
                        format!("couldn't create a named pipe in {}", pipe_)
                    }))
                }
            }

            try!(File::open(&pipe)
                .chain_err(|| format!("couldn't open {}", pipe_)))
        }
        #[cfg(not(unix))]
        () => {
            try!(OpenOptions::new()
                 .create(true)
                 .read(true)
                 .write(true)
                 .open(&pipe)
                 .chain_err(|| format!("couldn't open {}", pipe_)))
        }
    };

    let mut header = 0;

    let (stdout, stderr) = (io::stdout(), io::stderr());
    let (mut stdout, mut stderr) = (stdout.lock(), stderr.lock());
    loop {
        if let Err(e) = (|| {
            try!(stream.read_exact(ref_slice_mut(&mut header)));
            let port = header >> 3;

            // Ignore all the packets that don't come from the stimulus port 0
            if port != 0 {
                return Ok(());
            }

            match header & 0b111 {
                0b01 => {
                    let mut payload = 0;
                    try!(stream.read_exact(ref_slice_mut(&mut payload)));
                    stdout.write_all(&[payload])
                }
                0b10 => {
                    let mut payload = [0; 2];
                    try!(stream.read_exact(&mut payload));
                    stdout.write_all(&payload)
                }
                0b11 => {
                    let mut payload = [0; 4];
                    try!(stream.read_exact(&mut payload));
                    stdout.write_all(&payload)
                }
                _ => {
                    // Not a valid header, skip.
                    Ok(())
                }
            }
        })() {
            match e.kind() {
                io::ErrorKind::UnexpectedEof => {
                    thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    writeln!(stderr, "error: {:?}", e.kind()).unwrap();
                }
            }
        }
    }
}
