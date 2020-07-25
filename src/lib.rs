//! ITM packet parser
//!
//! # References
//!
//! - [ARMv7-M Architecture Reference Manual (DDI 0403E.b)][0] - Appendix D4 Debug ITM and DWT
//! Packet Protocol
//!
//! [0]: https://static.docs.arm.com/ddi0403/eb/DDI0403E_B_armv7m_arm.pdf
//!
//! - [CoreSight Components Technical Reference Manual (DDI 0314H)][1] - Chapter 12 Instrumentation
//! Trace Macrocell
//!
//! [1]: http://infocenter.arm.com/help/topic/com.arm.doc.ddi0314h/DDI0314H_coresight_components_trm.pdf

#![deny(missing_docs)]
#![deny(warnings)]

use core::fmt;
use std::io::{self, ErrorKind, Read};

use byteorder::{ByteOrder, LE};
use either::Either;
use thiserror::Error;

use crate::packet::{
    DataTraceAddress, DataTraceDataValue, DataTracePcValue, EventCounter, ExceptionTrace, Function,
    Instrumentation, LocalTimestamp, PeriodicPcSample, StimulusPortPage, Synchronization, GTS1,
    GTS2,
};

pub mod packet;
#[cfg(test)]
mod tests;

/// A stream of ITM packets
pub struct Stream<R>
where
    R: Read,
{
    // have we reached the EOF of the reader?
    at_eof: bool,
    // NOTE size is optimized for reading from `/dev/ttyUSB*`; `Read::read` usually reads in 32-byte
    // chunks
    buffer: [u8; 64],
    // whether to continue reading past a (temporary) EOF condition
    keep_reading: bool,
    // number of read bytes in `buffer`
    len: usize,
    reader: R,
}

impl<R> fmt::Debug for Stream<R>
where
    R: fmt::Debug + Read,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Stream")
            .field("at_eof", &self.at_eof)
            .field("buffer", &&self.buffer[..self.len])
            .field("keep_reading", &self.keep_reading)
            .field("reader", &self.reader)
            .finish()
    }
}

impl<R> Stream<R>
where
    R: Read,
{
    /// Creates a stream of ITM packets from the given `Reader` object
    ///
    /// If `keep_reading` is set to `true` the stream will continue to read to `Reader` object past
    /// (temporary) EOF conditions
    pub fn new(reader: R, keep_reading: bool) -> Stream<R> {
        Stream {
            buffer: [0; 64],
            at_eof: false,
            keep_reading,
            len: 0,
            reader,
        }
    }

    /// Returns the next packet in this stream
    ///
    /// The outer `Result` indicates I/O errors from reading from the inner `Reader` object.
    ///
    /// `Ok(None)` means that EOF has been reached -- this is only returned when `keep_reading` is
    /// set to `false` (see constructor)
    ///
    /// `Ok(Some(..))` is the result of parsing the stream data into an ITM packet
    pub fn next(&mut self) -> io::Result<Option<Result<Packet, Error>>> {
        if self.at_eof {
            return Ok(None);
        }

        'extract: loop {
            match parse(&self.buffer[..self.len]) {
                Ok(packet) => {
                    self.rotate_left(usize::from(packet.len()));

                    return Ok(Some(Ok(packet)));
                }
                // parsing error
                Err(Either::Left(e)) => {
                    // skip malformed packet
                    self.rotate_left(usize::from(e.len()));

                    return Ok(Some(Err(e)));
                }
                Err(Either::Right(NeedMoreBytes)) => {
                    // need more bytes
                    'read: loop {
                        match self.reader.read(&mut self.buffer[self.len..]) {
                            Ok(0) => {
                                if self.keep_reading {
                                    continue 'read;
                                } else {
                                    // reached EOF
                                    if self.len == 0 {
                                        return Ok(None);
                                    } else {
                                        // truncated packet
                                        self.at_eof = true;
                                        return Ok(Some(Err(Error::MalformedPacket {
                                            header: self.buffer[0],
                                            len: self.len as u8,
                                        })));
                                    }
                                }
                            }
                            Ok(len) => {
                                self.len += len;
                                // got more data; try to extract a packet again
                                continue 'extract;
                            }
                            Err(e) => match e.kind() {
                                ErrorKind::Interrupted => continue 'read,
                                _ => return Err(e),
                            },
                        }
                    }
                }
            }
        }
    }

    /// Gets a reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Gets a mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    // like `slice.rotate_left` but doesn't touch the unused parts of the buffer
    fn rotate_left(&mut self, shift: usize) {
        for i in 0..self.len - shift {
            self.buffer[i] = self.buffer[i + shift];
        }

        self.len -= shift;
    }
}

/// ITM packet decoding errors
#[derive(Debug, Error)]
pub enum Error {
    /// The packet starts with a reserved header byte
    #[error("reserved header byte: {byte}")]
    ReservedHeader {
        /// The header byte
        byte: u8,
    },

    /// The packet doesn't adhere to the (ARMv7-M) specification
    #[error("malformed packet of length {len} with header {header}")]
    MalformedPacket {
        /// The header of the malformed packet
        header: u8,
        /// Length of the malformed packet in bytes, including the header
        len: u8,
    },
}

impl Error {
    fn len(&self) -> u8 {
        match *self {
            Error::ReservedHeader { .. } => 1,
            Error::MalformedPacket { len, .. } => len,
        }
    }
}

/// An ITM packet
#[derive(Clone, Copy, Debug)]
pub enum Packet {
    /// Overflow packet
    Overflow,
    /// Synchronization packet
    Synchronization(Synchronization),
    /// Instrumentation packet
    Instrumentation(Instrumentation),
    /// Local timestamp packet
    LocalTimestamp(LocalTimestamp),
    /// Global timestamp packet (format 1)
    GTS1(GTS1),
    /// Global timestamp packet (format 2)
    GTS2(GTS2),
    /// Stimulus Port Page (Extension packet)
    StimulusPortPage(StimulusPortPage),
    /// Event Counter
    EventCounter(EventCounter),
    /// Exception Trace
    ExceptionTrace(ExceptionTrace),
    /// Periodic PC Sample
    PeriodicPcSample(PeriodicPcSample),
    /// Data Trace PC Value
    DataTracePcValue(DataTracePcValue),
    /// Data Trace Address
    DataTraceAddress(DataTraceAddress),
    /// Data Trace Address
    DataTraceDataValue(DataTraceDataValue),
}

impl Packet {
    /// The length of this packet in bytes, including the header
    fn len(&self) -> u8 {
        match *self {
            Packet::Overflow => 1,
            Packet::Synchronization(s) => s.len(),
            Packet::Instrumentation(i) => 1 /* header */ + i.size,
            Packet::LocalTimestamp(lt) => lt.len,
            Packet::GTS1(gt) => gt.len,
            Packet::GTS2(gt) => {
                if gt.b64 {
                    7
                } else {
                    5
                }
            }
            Packet::StimulusPortPage(_) => 1,
            Packet::EventCounter(_) => 2,
            Packet::ExceptionTrace(_) => 3,
            Packet::PeriodicPcSample(pps) => {
                if pps.pc().is_some() {
                    5
                } else {
                    2
                }
            }
            Packet::DataTracePcValue(_) => 5,
            Packet::DataTraceAddress(_) => 3,
            Packet::DataTraceDataValue(dtdv) => 1 /* header */ + dtdv.size,
        }
    }
}

/// Tries to parse an ITM packet from the start of the given buffer
fn parse(input: &[u8]) -> Result<Packet, Either<Error, NeedMoreBytes>> {
    let header = input.first().cloned().ok_or(Either::Right(NeedMoreBytes))?;

    match Header::parse(header).map_err(Either::Left)? {
        Header::Synchronization => {
            let mut cursor = 1u8;

            loop {
                match input.get(usize::from(cursor)) {
                    Some(&0b0000_0000) => {
                        // still within the synchronization packet
                        cursor += 1;
                        continue;
                    }
                    Some(&0b1000_0000) if cursor >= 5 => {
                        //  "Synchronization packet is at least forty-seven 0 bits followed by single 1
                        //  bit"
                        // valid synchronization packet
                        break Ok(Packet::Synchronization(Synchronization { len: cursor + 1 }));
                    }
                    Some(_) => {
                        // malformed packet
                        break Err(Either::Left(Error::MalformedPacket {
                            header,
                            len: cursor,
                        }));
                    }
                    None => {
                        // need more bytes
                        break Err(Either::Right(NeedMoreBytes));
                    }
                }
            }
        }

        // Overflow packets have no payload
        Header::Overflow => Ok(Packet::Overflow),

        Header::Instrumentation { port, size } => {
            let mut buffer = [0; 4];

            let usize = usize::from(size);
            if input.len() > usize {
                buffer[..usize].copy_from_slice(&input[1..=usize]);

                Ok(Packet::Instrumentation(Instrumentation {
                    buffer,
                    size,
                    port,
                }))
            } else {
                // need more bytes
                Err(Either::Right(NeedMoreBytes))
            }
        }

        Header::LTS1 { tc } => {
            // parse the payload
            let mut delta = 0;
            let mut cursor = 1u8;
            loop {
                let payload = input
                    .get(usize::from(cursor))
                    .cloned()
                    .ok_or(Either::Right(NeedMoreBytes))?;

                delta += (u32::from(payload) & 0b0111_1111) << (7 * (cursor - 1));

                if payload & 0b1000_0000 == 0 {
                    // the C (Continue) bit is zero; end of the packet
                    break;
                } else {
                    // the C (Continue) bit is set

                    if cursor == 4 {
                        // payloads are at most 4 bytes in size
                        // according to the spec the last C bit should be zero so this is an error

                        // the final payload byte may have been lost and this could be a new
                        // header byte so we consider the malformed packet to end at the third
                        // payload byte
                        return Err(Either::Left(Error::MalformedPacket {
                            header,
                            len: cursor,
                        }));
                    } else {
                        cursor += 1;
                        continue;
                    }
                }
            }

            Ok(Packet::LocalTimestamp(LocalTimestamp {
                delta,
                tc,
                len: cursor + 1,
            }))
        }

        Header::LTS2 { ts } => Ok(Packet::LocalTimestamp(LocalTimestamp {
            delta: u32::from(ts),
            tc: 0b00,
            len: 1,
        })),

        Header::GTS1 => {
            // parse the payload -- this is similar to parsing LTS1 payload
            let mut bits = 0;
            let mut clk_ch = false;
            let mut wrap = false;
            let mut cursor = 1u8;
            loop {
                let payload = input
                    .get(usize::from(cursor))
                    .cloned()
                    .ok_or(Either::Right(NeedMoreBytes))?;

                let mask = if cursor == 4 {
                    0b0001_1111
                } else {
                    0b0111_1111
                };
                bits += (u32::from(payload) & mask) << (7 * (cursor - 1));

                if payload & 0b1000_0000 == 0 {
                    // the C (Continue) bit is zero; end of the packet
                    if cursor == 4 {
                        // the fourth payload byte has extra info
                        clk_ch = payload & (1 << 5) != 0;
                        wrap = payload & (1 << 6) != 0;
                    }

                    break;
                } else {
                    // the C (Continue) bit is set

                    if cursor == 4 {
                        // payloads are at most 4 bytes in size
                        // according to the spec the last C bit should be zero so this is an error

                        // the final payload byte may have been lost and this could be a new
                        // header byte so we consider the malformed packet to end at the third
                        // payload byte
                        return Err(Either::Left(Error::MalformedPacket {
                            header,
                            len: cursor,
                        }));
                    } else {
                        cursor += 1;
                        continue;
                    }
                }
            }

            Ok(Packet::GTS1(GTS1 {
                bits,
                clk_ch,
                len: cursor + 1,
                wrap,
            }))
        }

        Header::GTS2 => {
            // parse the payload -- this is similar to parsing LTS1 payload
            let mut bits = 0;
            let mut cursor = 1u8;
            let b64 = loop {
                let payload = input
                    .get(usize::from(cursor))
                    .cloned()
                    .ok_or(Either::Right(NeedMoreBytes))?;

                bits += (u64::from(payload) & 0b0111_1111) << (7 * (cursor - 1));

                if payload & 0b1000_0000 == 0 {
                    // Continue (C) bit is zero
                    if cursor == 4 {
                        if payload >> 1 != 0 {
                            return Err(Either::Left(Error::MalformedPacket {
                                header,
                                len: cursor,
                            }));
                        } else {
                            break false;
                        }
                    } else if cursor == 6 {
                        if payload >> 3 != 0 {
                            return Err(Either::Left(Error::MalformedPacket {
                                header,
                                len: cursor,
                            }));
                        } else {
                            break true;
                        }
                    } else {
                        return Err(Either::Left(Error::MalformedPacket {
                            header,
                            len: cursor,
                        }));
                    }
                } else {
                    // Continue (C) bit is one
                    cursor += 1;
                }
            };

            Ok(Packet::GTS2(GTS2 { bits, b64 }))
        }

        Header::StimulusPortPage { page } => {
            Ok(Packet::StimulusPortPage(StimulusPortPage { page }))
        }

        Header::EventCounter => {
            let payload = input.get(1).cloned().ok_or(Either::Right(NeedMoreBytes))?;

            if payload >> 6 == 0 {
                Ok(Packet::EventCounter(EventCounter { payload }))
            } else {
                // assume that the payload was lost
                Err(Either::Left(Error::MalformedPacket { header, len: 1 }))
            }
        }

        Header::ExceptionTrace => {
            let mut payload = [0; 2];

            if input.len() >= 3 {
                payload.copy_from_slice(&input[1..3]);
            } else {
                return Err(Either::Right(NeedMoreBytes));
            }

            let mut number = u16::from(payload[0]);
            number += u16::from(payload[1] & 1) << 8;

            let function = match payload[1] >> 1 {
                0b000_1000 => Function::Enter,
                0b001_0000 => Function::Exit,
                0b001_1000 => Function::Return,
                // assume that the payload was lost
                _ => return Err(Either::Left(Error::MalformedPacket { header, len: 1 })),
            };

            Ok(Packet::ExceptionTrace(ExceptionTrace { function, number }))
        }

        Header::FullPeriodicPcSample => {
            if input.len() >= 5 {
                Ok(Packet::PeriodicPcSample(PeriodicPcSample {
                    pc: Some(LE::read_u32(&input[1..5])),
                }))
            } else {
                Err(Either::Right(NeedMoreBytes))
            }
        }

        Header::PeriodicPcSleep => {
            let payload = input.get(1).cloned().ok_or(Either::Right(NeedMoreBytes))?;

            if payload == 0 {
                Ok(Packet::PeriodicPcSample(PeriodicPcSample { pc: None }))
            } else {
                Err(Either::Left(Error::MalformedPacket { header, len: 1 }))
            }
        }

        Header::DataTracePcValue { cmpn } => {
            if input.len() >= 5 {
                Ok(Packet::DataTracePcValue(DataTracePcValue {
                    cmpn,
                    pc: LE::read_u32(&input[1..5]),
                }))
            } else {
                Err(Either::Right(NeedMoreBytes))
            }
        }

        Header::DataTraceAddress { cmpn } => {
            if input.len() >= 3 {
                Ok(Packet::DataTraceAddress(DataTraceAddress {
                    address: LE::read_u16(&input[1..3]),
                    cmpn,
                }))
            } else {
                Err(Either::Right(NeedMoreBytes))
            }
        }

        Header::DataTraceDataValue { cmpn, wnr, size } => {
            let mut buffer = [0; 4];

            let usize = usize::from(size);
            if input.len() > usize {
                buffer[..usize].copy_from_slice(&input[1..=usize]);

                Ok(Packet::DataTraceDataValue(DataTraceDataValue {
                    buffer,
                    cmpn,
                    size,
                    wnr,
                }))
            } else {
                Err(Either::Right(NeedMoreBytes))
            }
        }
    }
}

struct NeedMoreBytes;

#[derive(Debug)]
enum Header {
    /// D4.2.1 Synchronization packet
    Synchronization,

    /// D4.2.3 Overflow packet
    Overflow,

    /// D4.2.5 Global timestamp packets
    Instrumentation {
        port: u8,
        size: u8,
    },

    /// D4.2.4 Local timestamp packet format 1
    LTS1 {
        tc: u8,
    },
    /// D4.2.4 Local timestamp packet format 2
    LTS2 {
        ts: u8,
    },

    // D2.4.5 Global timestamp packets
    GTS1,
    GTS2,

    /// D4.2.6 Extension packet for the stimulus port page number
    StimulusPortPage {
        page: u8,
    },

    // D4.3 Hardware Source Packets
    /// D4.3.1 Event counter packet
    EventCounter,
    /// D4.3.2 Exception trace packet
    ExceptionTrace,
    /// D4.3.2 Periodic PC sample packets
    FullPeriodicPcSample,
    PeriodicPcSleep,

    /// D4.3.4 Data trace PC value packet
    DataTracePcValue {
        cmpn: u8,
    },
    /// D4.3.4 Data trace address packet
    DataTraceAddress {
        cmpn: u8,
    },
    /// D4.3.4 Data trace data value packet
    DataTraceDataValue {
        cmpn: u8,
        wnr: bool,
        size: u8,
    },
}

impl Header {
    fn parse(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0b0000_0000 => Header::Synchronization,

            0b0111_0000 => Header::Overflow,

            0b1001_0100 => Header::GTS1,
            0b1011_0100 => Header::GTS2,

            0b0000_0101 => Header::EventCounter,

            0b0000_1110 => Header::ExceptionTrace,

            0b0001_0111 => Header::FullPeriodicPcSample,
            0b0001_0101 => Header::PeriodicPcSleep,

            _ => {
                if byte & 0b1000_1111 == 0 {
                    // 0b0TSx_0000
                    let ts = (byte >> 4) & 0b111;

                    if ts != 0 && ts != 0b111 {
                        Header::LTS2 { ts }
                    } else {
                        // ts = 0 (Synchronization) and ts = 7 (Overflow) are handled above
                        unreachable!()
                    }
                } else if byte & 0b1100_1111 == 0b1100_0000 {
                    // 0b11TC_0000
                    let tc = (byte >> 4) & 0b11;
                    Header::LTS1 { tc }
                } else if byte & 0b1000_1111 == 0b0000_1000 {
                    // 0b0xxx_1000
                    let page = (byte >> 4) & 0b111;

                    Header::StimulusPortPage { page }
                } else {
                    // 0bAAAA_A0SS
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
                                // 0b01xx_0111
                                Header::DataTracePcValue { cmpn }
                            } else if byte & 0b1100_1111 == 0b0100_1110 {
                                // 0b01xx_1110
                                Header::DataTraceAddress { cmpn }
                            } else if byte & 0b1100_0100 == 0b1000_0100 {
                                // 0b01xx_W1SS
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
