extern crate tempdir;

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};

use tempdir::TempDir;

// NOTE the order of these fields is important. The file must be closed before
// destroying the temporary directory.
struct ItmDump {
    stdout: ChildStdout,
    child: Child,
    pipe: File,
    _td: TempDir,
}

impl ItmDump {
    pub fn new() -> ItmDump {
        let td = TempDir::new("itmdump").unwrap();
        let path = td.path().join("fifo");
        let mut me = env::current_exe().unwrap();
        me.pop();
        if me.ends_with("deps") {
            me.pop();
        }
        let mut child = Command::new(me.join("itmdump"))
            .arg(&path)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        while !path.exists() {}
        let pipe = OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap();

        ItmDump {
            pipe: pipe,
            stdout: child.stdout.take().unwrap(),
            _td: td,
            child: child,
        }
    }

    fn write_u8(&mut self, payload: u8) {
        self.pipe.write_all(&[0b01, payload]).unwrap();
        self.pipe.flush().unwrap();
    }

    fn write_u8x2(&mut self, payload: [u8; 2]) {
        self.pipe.write_all(&[0b10, payload[0], payload[1]]).unwrap()
    }

    fn write_u8x4(&mut self, payload: [u8; 4]) {
        self.pipe
            .write_all(&[0b11, payload[0], payload[1], payload[2], payload[3]])
            .unwrap()
    }

    fn read(&mut self, buffer: &mut [u8]) {
        self.stdout.read_exact(buffer).unwrap()
    }
}

impl Drop for ItmDump {
    fn drop(&mut self) {
        self.child.kill().unwrap()
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

    let mut buffer = [0u8; 13];
    itmdump.read(&mut buffer);

    assert_eq!(b"Hello, World\n", &buffer);

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

    let mut buffer = [0u8; 6];
    itmdump.read(&mut buffer);

    assert_eq!(b"Hello\n", &buffer);
}

#[test]
fn single() {
    let mut itmdump = ItmDump::new();
    itmdump.write_u8('\n' as u8);

    let mut buffer = [0u8];
    itmdump.read(&mut buffer);

    assert_eq!(b"\n", &buffer);
}
