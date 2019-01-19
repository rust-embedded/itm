//! Parse ITM packets from bytes and streams.

// NOTE: See ARMv7-M Architecture Reference Manual (DDI 0403E.b) for information about decoding ITM
// packets

use std::io::{self, Cursor, ErrorKind, Read};

use byteorder::{ByteOrder, LE};
use failure;

use packet::{
    self, DataTraceAddress, DataTraceDataValue, DataTracePcValue, EventCounter, ExceptionTrace,
    ExtensionStimulusPortPage, Function, Instrumentation, Kind, LocalTimestamp, Packet,
    PeriodicPcSample, Synchronization,
};
use Error;

/// Parses ITM packets.
pub struct Decoder<R: Read> {
    inner: R,
    follow: bool,
}

// Copy&Paste from std::io::Read::read_exact
fn read_exact<R>(reader: &mut R, mut buf: &mut [u8], keep_reading: bool) -> io::Result<()>
where
    R: Read,
{
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) if !keep_reading => break,
            Ok(0) if keep_reading => continue,
            Ok(n) => {
                let tmp = buf;
                buf = &mut tmp[n..];
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if !buf.is_empty() {
        Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
    } else {
        Ok(())
    }
}

fn read_exact_gently<R>(
    reader: &mut R,
    buf: &mut [u8],
    keep_reading: bool,
) -> Result<(), failure::Error>
where
    R: Read,
{
    match read_exact(reader, buf, keep_reading) {
        Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => Err(Error::EofDuringPacket.into()),
        Err(e) => Err(e.into()),
        Ok(_) => Ok(()),
    }
}

impl<R: Read> Decoder<R> {
    /// Construct a new `Decoder` that reads encoded packets from
    /// `inner`.
    pub fn new(inner: R, follow: bool) -> Decoder<R> {
        Decoder::<R> {
            inner: inner,
            follow: follow,
        }
    }

    // TODO: If we need config for the Decoder, my plan is to:
    // * Add a Config struct with private fields that can be used with
    //   `serde`, built with a builder pattern (`derive_builder` is
    //   great), or built with a Default implementation.
    // * Add a method Decoder.with_config(inner: R, config: Config).

    /// Read a single packet from the inner `Read`. This will block
    /// for input if no full packet is currently an available.
    pub fn read_packet(&mut self) -> Result<Packet, failure::Error> {
        let mut buf = [0];

        // like `read_exact_gently` but we return a different error variant
        match read_exact(&mut self.inner, &mut buf, self.follow) {
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => {
                return Err(Error::EofBeforePacket.into());
            }
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }

        let header = buf[0];
        match Header::parse(buf[0])? {
            Header::Synchronization => {
                let mut buf = [0];
                let mut count = 1;
                loop {
                    read_exact_gently(&mut self.inner, &mut buf, self.follow)?;

                    if buf[0] == 0b1000_0000 && count >= 6 {
                        break Ok(Packet {
                            header,
                            kind: Kind::Synchronization(Synchronization { bytes: count }),
                        });
                    } else if buf[0] == 0b0000_0000 {
                        count += 1;
                        continue;
                    } else {
                        return Err(Error::MalformedPacket { header }.into());
                    }
                }
            }

            Header::Overflow => Ok(Packet {
                header,
                kind: Kind::Overflow,
            }),

            Header::Instrumentation { port, size } => {
                let mut ip = Instrumentation {
                    payload: [0; packet::MAX_PAYLOAD_SIZE],
                    payload_len: size,
                    port,
                };

                read_exact_gently(&mut self.inner, &mut ip.payload[0..size], self.follow)?;

                Ok(Packet {
                    header: header,
                    kind: packet::Kind::Instrumentation(ip),
                })
            }

            Header::LTS1 { tc } => {
                let mut delta = 0;
                let mut buf = [0];

                // first payload byte
                read_exact_gently(&mut self.inner, &mut buf, self.follow)?;
                delta += u32::from(buf[0]) & (0b0111_1111);

                if buf[0] & 0b1000_0000 != 0 {
                    // C (Continue) bit is set

                    // second payload byte
                    read_exact_gently(&mut self.inner, &mut buf, self.follow)?;
                    delta += (u32::from(buf[0]) & (0b0111_1111)) << 7;

                    if buf[0] & 0b1000_0000 != 0 {
                        // C (Continue) bit is set

                        // third payload byte
                        read_exact_gently(&mut self.inner, &mut buf, self.follow)?;
                        delta += (u32::from(buf[0]) & (0b0111_1111)) << 14;

                        if buf[0] & 0b1000_0000 != 0 {
                            // C (Continue) bit is set

                            // fourth payload byte
                            read_exact_gently(&mut self.inner, &mut buf, self.follow)?;

                            // according to the spec C should be zero
                            if buf[0] & 0b0111_1111 == 0 {
                                delta += (u32::from(buf[0]) & (0b0111_1111)) << 21;
                            } else {
                                return Err(Error::MalformedPacket { header }.into());
                            }
                        }
                    }
                }

                Ok(Packet {
                    header,
                    kind: packet::Kind::LocalTimestamp(LocalTimestamp { delta, tc }),
                })
            }

            Header::LTS2 { ts } => Ok(Packet {
                header,
                kind: packet::Kind::LocalTimestamp(LocalTimestamp {
                    delta: u32::from(ts),
                    tc: 0b00,
                }),
            }),

            Header::GTS1 | Header::GTS2 => unimplemented!(),

            Header::StimulusPortPage { page } => Ok(Packet {
                header,
                kind: packet::Kind::ExtensionStimulusPortPage(ExtensionStimulusPortPage { page }),
            }),

            Header::EventCounter => {
                let mut buf = [0];
                read_exact_gently(&mut self.inner, &mut buf, self.follow)?;

                let payload = buf[0];
                if payload >> 6 == 0b00 {
                    return Err(Error::MalformedPacket { header }.into());
                } else {
                    Ok(Packet {
                        header,
                        kind: packet::Kind::EventCounter(EventCounter { payload }),
                    })
                }
            }

            Header::ExceptionTrace => {
                let mut buf = [0; 2];
                read_exact_gently(&mut self.inner, &mut buf, self.follow)?;

                let mut number = u16::from(buf[0]);
                number += u16::from(buf[1] & 1) << 8;

                let function = match buf[1] >> 1 {
                    0b0001_000 => Function::Enter,
                    0b0010_000 => Function::Exit,
                    0b0011_000 => Function::Return,
                    _ => return Err(Error::MalformedPacket { header }.into()),
                };

                Ok(Packet {
                    header,
                    kind: packet::Kind::ExceptionTrace(ExceptionTrace { number, function }),
                })
            }

            Header::FullPeriodicPcSample => {
                let mut buf = [0; 4];
                read_exact_gently(&mut self.inner, &mut buf, self.follow)?;

                Ok(Packet {
                    header,
                    kind: packet::Kind::PeriodicPcSample(PeriodicPcSample {
                        pc: Some(LE::read_u32(&buf)),
                    }),
                })
            }

            Header::PeriodicPcSleep => {
                let mut buf = [0];
                read_exact_gently(&mut self.inner, &mut buf, self.follow)?;

                if buf[0] != 0 {
                    return Err(Error::MalformedPacket { header }.into());
                }

                Ok(Packet {
                    header,
                    kind: packet::Kind::PeriodicPcSample(PeriodicPcSample { pc: None }),
                })
            }

            Header::DataTracePcValue { cmpn } => {
                let mut buf = [0; 4];
                read_exact_gently(&mut self.inner, &mut buf, self.follow)?;

                Ok(Packet {
                    header,
                    kind: packet::Kind::DataTracePcValue(DataTracePcValue {
                        pc: LE::read_u32(&buf),
                        cmpn,
                    }),
                })
            }

            Header::DataTraceAddress { cmpn } => {
                let mut buf = [0; 2];
                read_exact_gently(&mut self.inner, &mut buf, self.follow)?;

                Ok(Packet {
                    header,
                    kind: packet::Kind::DataTraceAddress(DataTraceAddress {
                        addr: LE::read_u16(&buf),
                        cmpn,
                    }),
                })
            }

            Header::DataTraceDataValue { cmpn, wnr, size } => {
                let mut payload = [0; 4];
                read_exact_gently(&mut self.inner, &mut payload[..size], self.follow)?;

                Ok(Packet {
                    header,
                    kind: packet::Kind::DataTraceDataValue(DataTraceDataValue {
                        cmpn,
                        len: size,
                        payload,
                        wnr,
                    }),
                })
            }
        }
    }
}

#[derive(Debug)]
enum Header {
    Synchronization,
    Overflow,

    Instrumentation {
        port: u8,
        size: usize,
    },

    /// D2.4.4 Local timestamp packets
    LTS1 {
        tc: u8,
    },
    LTS2 {
        ts: u8,
    },

    // D2.4.5 Global timestamp packets
    GTS1,
    GTS2,

    // D4.2.6
    StimulusPortPage {
        page: u8,
    },

    // D4.3 Hardware Source Packets
    EventCounter,
    ExceptionTrace,
    FullPeriodicPcSample,
    PeriodicPcSleep,

    // D4.3.4 Data trace packets
    DataTracePcValue {
        cmpn: u8,
    },
    DataTraceAddress {
        cmpn: u8,
    },
    DataTraceDataValue {
        cmpn: u8,
        wnr: bool,
        size: usize,
    },
}

impl Header {
    fn parse(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            // D4.2.1 Synchronization packet
            0b0000_0000 => Header::Synchronization,

            // D4.2.3 Overflow packet
            0b0111_0000 => Header::Overflow,

            // D2.4.5 Global timestamp packets
            0b1001_0100 => Header::GTS1,
            0b1011_0100 => Header::GTS2,

            // D4.3.1 Event counter packet
            0b0000_0101 => Header::EventCounter,

            // D4.3.2 Exception trace packet
            0b0000_1110 => Header::ExceptionTrace,

            // D4.3.2 Periodic PC sample packets
            0b0001_0111 => Header::FullPeriodicPcSample,
            0b0001_0101 => Header::PeriodicPcSleep,

            _ => {
                if byte & 0b1000_1111 == 0 {
                    // D4.2.4 Local timestamp packet format 2 - 0b0TSx_0000
                    let ts = (byte >> 4) & 0b111;

                    if ts != 0 && ts != 0b111 {
                        Header::LTS2 { ts }
                    } else {
                        // ts = 0 (Synchronization) and ts = 7 (Overflow) are handled above
                        unreachable!()
                    }
                } else if byte & 0b1100_1111 == 0b1100_0000 {
                    // D4.2.4 Local timestamp packet format 1 - 0b11TC_0000
                    let tc = (byte >> 4) & 0b11;
                    Header::LTS1 { tc }
                } else if byte & 0b1000_1111 == 0b0000_1000 {
                    // D4.2.6 Extension packet for the stimulus port page number - 0b0xxx_1000
                    let page = (byte >> 4) & 0b111;

                    Header::StimulusPortPage { page }
                } else {
                    // D4.2.8 Instrumentation packet - 0bAAAA_A0SS
                    match byte & 0b111 {
                        0b001 | 0b010 | 0b011 => {
                            let port = byte >> 3;
                            let size = match byte & 0b11 {
                                0b01 => 1,
                                0b10 => 2,
                                0b11 => 4,
                                _ => unreachable!(),
                            };

                            Header::Instrumentation { port, size }
                        }
                        _ => {
                            let cmpn = (byte >> 4) & 0b11;
                            if byte & 0b1100_1111 == 0b0100_0111 {
                                // D4.3.4 Data trace PC value packet - 0b01xx_0111
                                Header::DataTracePcValue { cmpn }
                            } else if byte & 0b1100_1111 == 0b0100_1110 {
                                // D4.3.4 Data trace address packet - 0b01xx_1110
                                Header::DataTraceAddress { cmpn }
                            } else if byte & 0b1100_0100 == 0b0100_0100 {
                                // D4.3.4 Data trace data value packet - 0b01xx_W1SS
                                match byte & 0b11 {
                                    0b01 | 0b10 | 0b11 => {
                                        let size = match byte & 0b11 {
                                            0b01 => 1,
                                            0b10 => 2,
                                            0b11 => 4,
                                            _ => unreachable!(),
                                        };

                                        let wnr = byte & (1 << 3) != 0;

                                        Header::DataTraceDataValue { cmpn, wnr, size }
                                    }
                                    0b00 => {
                                        return Err(Error::ReservedHeader { byte });
                                    }
                                    _ => unreachable!(),
                                }
                            } else {
                                return Err(Error::ReservedHeader { byte });
                            }
                        }
                    }
                }
            }
        })
    }
}

/// Decode a single packet from a slice of bytes.
pub fn from_slice(s: &[u8]) -> Result<Packet, failure::Error> {
    let mut d = Decoder::new(Cursor::new(Vec::from(s)), false);
    d.read_packet()
}

#[cfg(test)]
mod tests {
    use super::from_slice;

    use failure;

    use packet::{Function, Kind, Packet};
    use Error;

    #[test]
    fn header() {
        let p = decode_one(&[0x01, 0x11]);
        assert_eq!(p.header, 0x01);
    }

    #[test]
    fn exception_tracing() {
        let p = decode_one(&[0x0e, 0x16, 0x10]);
        match p.kind {
            Kind::ExceptionTrace(ref et) => {
                assert_eq!(et.number(), 0x16);
                assert_eq!(et.function(), Function::Enter);
            }
            _ => panic!(),
        }

        let p = decode_one(&[0x0e, 0x17, 0x20]);
        match p.kind {
            Kind::ExceptionTrace(ref et) => {
                assert_eq!(et.number(), 0x17);
                assert_eq!(et.function(), Function::Exit);
            }
            _ => panic!(),
        }

        let p = decode_one(&[0x0e, 0x16, 0x30]);
        match p.kind {
            Kind::ExceptionTrace(ref et) => {
                assert_eq!(et.number(), 0x16);
                assert_eq!(et.function(), Function::Return);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn instrumentation_payload_1_byte() {
        let p = decode_one(&[0x01, 0x11]);
        match p.kind {
            Kind::Instrumentation(ref i) => {
                assert_eq!(i.payload(), [0x11]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn instrumentation_payload_2_bytes() {
        let p = decode_one(&[0x02, 0x11, 0x12]);
        match p.kind {
            Kind::Instrumentation(ref i) => {
                assert_eq!(i.payload(), [0x11, 0x12]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn instrumentation_payload_4_bytes() {
        let p = decode_one(&[0x03, 0x11, 0x12, 0x13, 0x14]);
        match p.kind {
            Kind::Instrumentation(ref i) => {
                assert_eq!(i.payload(), [0x11, 0x12, 0x13, 0x14]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn instrumentation_stim_port() {
        let p = decode_one(&[0b00000_001, 0x11]);
        match p.kind {
            Kind::Instrumentation(ref i) => {
                assert_eq!(i.port(), 0);
            }
            _ => panic!(),
        }

        let p = decode_one(&[0b11111_001, 0x11]);
        match p.kind {
            Kind::Instrumentation(ref i) => {
                assert_eq!(i.port(), 31);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn local_timestamp() {
        let p = decode_one(&[0xc0, 0x5c]);
        match p.kind {
            Kind::LocalTimestamp(ref lt) => {
                assert_eq!(lt.delta(), 0x5c);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn reserved_header() {
        if let Err(e) = try_decode_one(&[0b0111_0100]) {
            match e.downcast_ref::<Error>() {
                Some(Error::ReservedHeader { byte: 0b0111_0100 }) => return (),
                _ => {}
            }
        }

        panic!()
    }

    #[test]
    fn eof_before_payload() {
        if let Err(e) = try_decode_one(&[0x01 /* Missing payload bytes */]) {
            match e.downcast_ref::<Error>() {
                Some(Error::EofDuringPacket) => return (),
                _ => {}
            }
        }

        panic!()
    }

    #[test]
    fn eof_before_packet() {
        if let Err(e) = try_decode_one(&[/* Missing packet bytes */]) {
            match e.downcast_ref::<Error>() {
                Some(Error::EofBeforePacket) => return (),
                _ => {}
            }
        }

        panic!()
    }

    fn decode_one(data: &[u8]) -> Packet {
        try_decode_one(data).unwrap()
    }

    fn try_decode_one(data: &[u8]) -> Result<Packet, failure::Error> {
        let p = from_slice(data);
        println!("{:#?}", p);
        p
    }
}
