extern crate ref_slice;

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs, io, process};

fn main() {
    let pipe = &PathBuf::from(env::args_os()
        .skip(1)
        .next()
        .unwrap_or_else(|| exit("expected one argument: the path to the named pipe")));

    if pipe.exists() {
        fs::remove_file(pipe)
            .unwrap_or_else(|_| exit(&format!("couldn't remove {}", pipe.display())));
    }

    let output = Command::new("mkfifo").arg(pipe).output().unwrap_or_else(|_| {
        exit("`mkfifo` not found");
    });

    if !output.status.success() {
        exit(&String::from_utf8_lossy(&output.stderr))
    }

    let mut stream = File::open(pipe)
        .unwrap_or_else(|_| exit(&format!("couldn't open {}", pipe.display())));

    let mut header = 0;

    let (stdout, stderr) = (io::stdout(), io::stderr());
    let (mut stdout, mut stderr) = (stdout.lock(), stderr.lock());
    loop {
        if let Err(e) = (|| {
            try!(stream.read_exact(ref_slice::ref_slice_mut(&mut header)));
            let port = header >> 3;

            // Ignore all the packets that don't come from the stimulus port 0
            if port != 0 {
                return Ok(());
            }

            match header & 0b111 {
                0b01 => {
                    let mut payload = 0;
                    try!(stream.read_exact(ref_slice::ref_slice_mut(&mut payload)));
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

fn exit(msg: &str) -> ! {
    let stderr = io::stderr();
    writeln!(stderr.lock(), "{}", msg).ok();
    process::exit(1)
}
