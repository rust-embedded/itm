#![deny(warnings)]

extern crate tempdir;

use std::env;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process::{Command, Output, Stdio};

use tempdir::TempDir;

// NOTE the order of these fields is important. The file must be closed before
// destroying the temporary directory.
struct ItmDump {
    command: Command,
    file: File,
    _td: TempDir,
}

impl ItmDump {
    pub fn new() -> ItmDump {
        let td = TempDir::new("itmdump").unwrap();
        let path = td.path().join("file");
        let mut me = env::current_exe().unwrap();
        me.pop();
        if me.ends_with("deps") {
            me.pop();
        }
        let mut command = Command::new(me.join("itmdump"));
        command.arg("-f").arg(&path).stdout(Stdio::piped());

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(path)
            .unwrap();

        ItmDump {
            file: file,
            _td: td,
            command: command,
        }
    }

    fn write_u8(&mut self, payload: u8) {
        self.file.write_all(&[0b01, payload]).unwrap();
        self.file.flush().unwrap();
    }

    fn write_u8x2(&mut self, payload: [u8; 2]) {
        self.file
            .write_all(&[0b10, payload[0], payload[1]])
            .unwrap();
        self.file.flush().unwrap();
    }

    fn write_u8x4(&mut self, payload: [u8; 4]) {
        self.file
            .write_all(&[0b11, payload[0], payload[1], payload[2], payload[3]])
            .unwrap();
        self.file.flush().unwrap();
    }

    fn output(&mut self) -> Output {
        self.command.output().unwrap()
    }
}

#[test]
fn chunks() {
    let mut itmdump = ItmDump::new();
    itmdump.write_u8('H' as u8);
    itmdump.write_u8x2(*b"el");
    itmdump.write_u8x4(*b"lo, ");
    itmdump.write_u8x4(*b"Worl");
    itmdump.write_u8x2(*b"d\n");

    let out = itmdump.output();

    assert_eq!(*b"Hello, World\n", *out.stdout);
}

#[test]
fn multiple() {
    let mut itmdump = ItmDump::new();
    itmdump.write_u8('H' as u8);
    itmdump.write_u8('e' as u8);
    itmdump.write_u8('l' as u8);
    itmdump.write_u8('l' as u8);
    itmdump.write_u8('o' as u8);
    itmdump.write_u8('\n' as u8);

    let out = itmdump.output();

    assert_eq!(*b"Hello\n", *out.stdout);
}

#[test]
fn single() {
    let mut itmdump = ItmDump::new();
    itmdump.write_u8('\n' as u8);

    let out = itmdump.output();

    assert_eq!(*b"\n", *out.stdout);
}
