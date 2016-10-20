extern crate clap;
extern crate libc;
extern crate ref_slice;

#[macro_use]
extern crate error_chain;

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::{env, fs, io, process};

use clap::{App, Arg};
use ref_slice::ref_slice_mut;

use errors::*;

mod errors {
    error_chain!();
}

fn main() {
    if let Err(e) = run() {
        let stderr = io::stderr();
        let mut stderr = stderr.lock();

        writeln!(stderr, "{}", e).ok();

        for e in e.iter().skip(1) {
            writeln!(stderr, "caused by: {}", e).ok();
        }

        if show_backtrace() {
            if let Some(backtrace) = e.backtrace() {
                writeln!(stderr, "backtrace:").ok();
                writeln!(stderr, "{:?}", backtrace).ok();
            }
        }

        process::exit(1)
    }
}

fn run() -> Result<()> {
    let matches = App::new("itmdump")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(Arg::with_name("PATH").help("Named pipe to use").required(true))
        .get_matches();

    let pipe = PathBuf::from(matches.value_of("PATH").unwrap());
    let pipe_ = pipe.display();

    if pipe.exists() {
        try!(fs::remove_file(&pipe)
            .chain_err(|| format!("couldn't remove {}", pipe_)));
    }

    let cpipe = try!(CString::new(pipe.clone().into_os_string().into_vec())
        .chain_err(|| format!("error converting {} to a C string", pipe_)));

    match unsafe { libc::mkfifo(cpipe.as_ptr(), 0o644) } {
        0 => {}
        e => {
            try!(Err(io::Error::from_raw_os_error(e)).chain_err(|| {
                format!("couldn't create a named pipe in {}", pipe_)
            }))
        }
    }

    let mut stream = try!(File::open(&pipe)
        .chain_err(|| format!("couldn't open {}", pipe_)));

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
            writeln!(stderr, "error: {}", e).ok();
        }
    }
}

fn show_backtrace() -> bool {
    env::var("RUST_BACKTRACE").as_ref().map(|s| &s[..]) == Ok("1")
}
