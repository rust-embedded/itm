//! Parse ITM packets from bytes and streams.

use error::{Error, ErrorKind, Result};
use heapless::Vec as HVec;
use packet::{self, Packet, Instrumentation};
use std::io::Read;

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

// TODO: Parse tests.
