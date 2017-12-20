//! Parse ITM packets from bytes and streams.

use error::{Error, ErrorKind, Result};
use heapless::Vec as HVec;
use packet::{self, Packet, Instrumentation};
use std::io::{Cursor, Read};

/// Parses ITM packets.
pub struct Decoder<R: Read> {
    inner: R,
}

impl<R: Read> Decoder<R> {
    /// Construct a new `Decoder` that reads encoded packets from
    /// `inner`.
    pub fn new(inner: R) -> Decoder<R> {
        Decoder::<R> {
            inner: inner,
        }
    }

    // TODO: If we need config for the Decoder, my plan is to:
    // * Add a Config struct with private fields that can be used with
    //   `serde`, built with a builder pattern (`derive_builder` is
    //   great), or built with a Default implementation.
    // * Add a method Decoder.with_config(inner: R, config: Config).

    /// Read a single packet from the inner `Read`. This will block
    /// for input if no full packet is currently an available.
    pub fn read_packet(&mut self) -> Result<Packet> {
        let mut header = [0; 1];
        self.inner.read_exact(&mut header)?;
        let header = header[0];
        match header & 0b111 {
            0b001|0b010|0b011 => {
                // Instrumentation packet.
                let mut ud = Instrumentation {
                    payload: HVec::new(),
                    port: header >> 3,
                };

                let payload_size =
                    match header & 0b11 {
                        0b01 => 1,
                        0b10 => 2,
                        0b11 => 4,
                        _ => unreachable!(), // Contradicts match on last 3 bits.
                    };
                ud.payload.resize_default(payload_size)
                    .expect("payload_size <= payload.capacity");
                self.inner.read_exact(&mut *ud.payload)?;

                Ok(Packet {
                    header: header,
                    kind: packet::Kind::Instrumentation(ud),
                })
            },
            _ => {
                return Err(Error::from(ErrorKind::UnknownHeader(header)));
            }
        }
    }
}

/// Decode a single packet from a slice of bytes.
pub fn from_slice(s: &[u8]) -> Result<Packet> {
    let mut d = Decoder::new(Cursor::new(Vec::from(s)));
    d.read_packet()
}

#[cfg(test)]
mod tests {
    use super::from_slice;
    use error::{Error, ErrorKind, Result};
    use packet::{Kind, Packet};
    use std::io;

    #[test]
    fn header() {
        let p = decode_one(&[0x01, 0x11]);
        assert_eq!(p.header, 0x01);
    }

    #[test]
    fn instrumentation_payload_1_byte() {
        let p = decode_one(&[0x01, 0x11]);
        match p.kind {
            Kind::Instrumentation(ref i) => {
                assert_eq!(*i.payload, [0x11]);
            },
            _ => panic!()
        }
    }

    #[test]
    fn instrumentation_payload_2_bytes() {
        let p = decode_one(&[0x02, 0x11, 0x12]);
        match p.kind {
            Kind::Instrumentation(ref i) => {
                assert_eq!(*i.payload, [0x11, 0x12]);
            },
            _ => panic!()
        }
    }

    #[test]
    fn instrumentation_payload_4_bytes() {
        let p = decode_one(&[0x03, 0x11, 0x12, 0x13, 0x14]);
        match p.kind {
            Kind::Instrumentation(ref i) => {
                assert_eq!(*i.payload, [0x11, 0x12, 0x13, 0x14]);
            },
            _ => panic!()
        }
    }

    #[test]
    fn instrumentation_stim_port() {
        let p = decode_one(&[0b00000_001, 0x11]);
        match p.kind {
            Kind::Instrumentation(ref i) => {
                assert_eq!(i.port, 0);
            },
            _ => panic!()
        }

        let p = decode_one(&[0b11111_001, 0x11]);
        match p.kind {
            Kind::Instrumentation(ref i) => {
                assert_eq!(i.port, 31);
            },
            _ => panic!()
        }
    }

    #[test]
    fn unknown_header() {
        let p = try_decode_one(&[0x00]);
        match p {
            Err(Error(ErrorKind::UnknownHeader(0x00), _)) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn eof_before_payload() {
        let p = try_decode_one(&[0x01 /* Missing payload bytes */ ]);
        match p {
            Err(Error(ErrorKind::Io(ref e), _))
            if e.kind() == io::ErrorKind::UnexpectedEof => (),
            _ => panic!(),
        }
    }

    fn decode_one(data: &[u8]) -> Packet {
        try_decode_one(data).unwrap()
    }

    fn try_decode_one(data: &[u8]) -> Result<Packet> {
        let p = from_slice(data);
        println!("{:#?}", p);
        p
    }
}
