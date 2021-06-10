//! A [sans-I/O](https://sans-io.readthedocs.io/how-to-sans-io.html)
//! decoder for the ITM and DWT packet protocol as specifed in the
//! [ARMv7-M architecture reference manual, Appendix
//! D4](https://developer.arm.com/documentation/ddi0403/ed/). Any
//! references in this code base refers to this document.
//!
//! Common abbreviations:
//!
//! - ITM: instrumentation trace macrocell;
//! - PC: program counter;
//! - DWT: data watchpoint and trace unit;
//! - MSB: most significant bit;
//! - BE: big-endian;

use bitmatch::bitmatch;
use bitvec::prelude::*;
use std::convert::TryInto;

#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

/// The set of possible packet types that may be decoded.
///
/// Specification would suggest an implementation of two enum types, but
/// that structure is here flattened to simplify the implementation.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum TracePacket {
    // Synchronization packet category (Appendix D4, p. 782)
    /// A synchronization packet is a unique pattern in the bitstream.
    /// It is identified and used to provide the alignment of other
    /// packet bytes in the bitstream. (Appendix D4.2.1)
    Sync,

    // Protocol packet category (Appendix D4, p. 782)
    /// Found in the bitstream if
    ///
    /// - Software has written to an ITM stimulus port register when the
    /// stimulus port output buffer is full.
    /// - The DWT attempts to generate a hardware source packet when the
    /// DWT output buffer is full.
    /// - The local timestamp counter overflows.
    ///
    /// See (Appendix D4.2.3).
    Overflow,

    /// A delta timestamp that measures the interval since the
    /// generation of the last local timestamp and its relation to the
    /// corresponding ITM/DWT data packets. (Appendix D4.2.4)
    LocalTimestamp1 {
        /// Timestamp value.
        ts: u64,

        /// Indicates the relationship between the generation of `ts`
        /// and the corresponding ITM or DWT data packet.
        data_relation: TimestampDataRelation,
    },

    /// A derivative of `LocalTimestamp1` for timestamp values between
    /// 1-6. Always synchronous to te associated ITM/DWT data. (Appendix D4.2.4)
    LocalTimestamp2 {
        /// Timestamp value.
        ts: u8,
    },

    /// An absolute timestamp based on the global timestamp clock that
    /// contain the timestamp's lower-order bits. (Appendix D4.2.5)
    GlobalTimestamp1 {
        /// Lower-order bits of the timestamp; bits\[25:0\].
        ts: u64,

        /// Set if higher order bits output by the last GTS2 have
        /// changed.
        wrap: bool,

        /// Set if the system has asserted a clock change input to the
        /// processor since the last generated global timestamp.
        clkch: bool,
    },

    /// An absolute timestamp based on the global timestamp clock that
    /// contain the timestamp's higher-order bits. (Appendix D4.2.5)
    GlobalTimestamp2 {
        /// Higher-order bits of the timestamp value; bits\[63:26\] or
        /// bits\[47:26\] depending on implementation.
        ts: u64,
    },

    /// A packet that provides additional information about the
    /// identified source (one of two possible, theoretically). On
    /// ARMv7-M this packet is only used to denote on which ITM stimulus
    /// port a payload was written. (Appendix D4.2.6)
    Extension {
        /// Source port page number.
        page: u8,
    },

    // Source packet category
    /// Contains the payload written to the ITM stimulus ports.
    Instrumentation {
        /// Stimulus port number.
        port: u8,

        /// Instrumentation data written to the stimulus port. MSB, BE.
        payload: Vec<u8>,
    },

    /// One or more event counters have wrapped. (Appendix D4.3.1)
    EventCounterWrap {
        /// POSTCNT wrap (see Appendix C1, p. 732).
        cyc: bool,
        /// FOLDCNT wrap (see Appendix C1, p. 734).
        fold: bool,
        /// LSUCNT wrap (see Appendix C1, p. 734).
        lsu: bool,
        /// SLEEPCNT wrap (see Appendix C1, p. 734).
        sleep: bool,
        /// EXCCNT wrap (see Appendix C1, p. 734).
        exc: bool,
        /// CPICNT wrap (see Appendix C1, p. 734).
        cpi: bool,
    },

    /// The processor has entered, exit, or returned to an exception.
    /// (Appendix D4.3.2)
    ExceptionTrace {
        exception: ExceptionType,
        action: ExceptionAction,
    },

    /// Periodic PC sample. (Appendix D4.3.3)
    PCSample {
        /// The value of the PC. `None` if periodic PC sleep packet.
        pc: Option<u32>,
    },

    /// A DWT comparator matched a PC value. (Appendix D4.3.4)
    DataTracePC {
        /// The comparator number that generated the data.
        comparator: u8,

        /// The PC value for the instruction that caused the successful
        /// address comparison.
        pc: u32,
    },

    /// A DWT comparator matched an address. (Appendix D4.3.4)
    DataTraceAddress {
        /// The comparator number that generated the data.
        comparator: u8,

        /// Data address content; bits\[15:0\]. MSB, BE.
        data: Vec<u8>,
    },

    /// A data trace packet with a value. (Appendix D4.3.4)
    DataTraceValue {
        /// The comparator number that generated the data.
        comparator: u8,

        /// Whether the data was read or written.
        access_type: MemoryAccessType,

        /// The data value. MSB, BE.
        value: Vec<u8>,
    },
}

/// Denotes the exception action taken by the processor. (Table D4-6)
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum ExceptionAction {
    /// Exception was entered.
    Entered,

    /// Exception was exited.
    Exited,

    /// Exception was returned to.
    Returned,
}

/// Denotes the exception type (interrupt event) of the processor.
/// (Table B1-4)
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum ExceptionType {
    Reset,
    Nmi,
    HardFault,
    MemManage,
    BusFault,
    UsageFault,
    SVCall,
    DebugMonitor,
    PendSV,
    SysTick,
    ExternalInterrupt(usize),
}

/// Denotes the type of memory access.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum MemoryAccessType {
    /// Memory was read.
    Read,

    /// Memory was written.
    Write,
}

/// Indicates the relationship between the generation of the local
/// timestamp packet and the corresponding ITM or DWT data packet.
/// (Appendix D4.2.4)
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum TimestampDataRelation {
    /// The local timestamp value is synchronous to the corresponding
    /// ITM or DWT data. The value in the TS field is the timestamp
    /// counter value when the ITM or DWT packet is generated.
    Sync,

    /// The local timestamp value is delayed relative to the ITM or DWT
    /// data. The value in the TS field is the timestamp counter value
    /// when the Local timestamp packet is generated.
    ///
    /// Note: the local timestamp value corresponding to the previous
    /// ITM or DWT packet is unknown, but must be between the previous
    /// and the current local timestamp values.
    UnknownDelay,

    /// Output of the ITM or DWT packet corresponding to this Local
    /// timestamp packet is delayed relative to the associated event.
    /// The value in the TS field is the timestamp counter value when
    /// the ITM or DWT packets is generated.
    ///
    /// This encoding indicates that the ITM or DWT packet was delayed
    /// relative to other trace output packets.
    AssocEventDelay,

    /// Output of the ITM or DWT packet corresponding to this Local
    /// timestamp packet is delayed relative to the associated event,
    /// and this Local timestamp packet is delayed relative to the ITM
    /// or DWT data. This is a combined condition of `UnknownDelay` and
    /// `AssocEventDelay`.
    UnknownAssocEventDelay,
}

/// A header or payload byte failed to be decoded. The state of the
/// decoder is now in an unknown state and manual intervention is
/// required.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum DecoderError {
    /// Header is invalid and cannot be decoded.
    InvalidHeader(u8),

    /// The type discriminator ID in the hardware source packet header
    /// is invalid or the associated payload is of wrong size.
    InvalidHardwarePacket {
        /// The discriminator ID. Potentially invalid.
        disc_id: u8,

        /// Associated payload. Potentially invalid length. MSB, BE.
        payload: Vec<u8>,
    },

    /// The type discriminator ID in the hardware source packet header
    /// is invalid.
    InvalidHardwareDisc {
        /// The discriminator ID. Potentially invalid.
        disc_id: u8,

        /// Associated payload length.
        size: usize,
    },

    /// An exception trace packet refers to an invalid action or an
    /// invalid exception number.
    InvalidExceptionTrace {
        /// The exception number.
        exception: u16,

        /// Numerical representation of the function associated with the
        /// exception number.
        function: u8,
    },

    /// The payload length of a PCSample packet is invalid.
    InvalidPCSampleSize {
        /// The payload constituting the PC value, of invalid size. MSB, BE.
        payload: Vec<u8>,
    },

    /// The GlobalTimestamp2 packet does not contain a 48-bit or 64-bit
    /// timestamp.
    InvalidGTS2Size {
        /// The payload constituting the timestamp, of invalid size. MSB, BE.
        payload: Vec<u8>,
    },

    /// The number of zeroes in the Synchronization packet is less than
    /// 47.
    InvalidSyncSize(usize),

    /// A source packet (from software or hardware) contains an invalid
    /// expected payload size.
    InvalidSourcePayload {
        /// The header which contains the invalid payload size.
        header: u8,

        /// The invalid payload size. See (Appendix D4.2.8, Table D4-4).
        size: u8,
    },
}

/// ITM and DWT packet protocol decoder.
pub struct Decoder {
    /// The incoming bytes to the decoder.
    pub incoming: BitVec,

    /// The current state of the decoder.
    pub state: DecoderState,
}

/// The decoder's possible states. The default decoder state is `Header`
/// and will always return there after a maximum of two steps. (E.g. if
/// the current state is `Syncing` or `HardwareSource`, the next state
/// is `Header` again.)
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum DecoderState {
    /// Next byte will be decoded as a header byte.
    Header,

    /// Next zero bits will be assumed to be part of a a Synchronization
    /// packet until a one is encountered.
    Syncing(usize),

    /// Next bytes will be assumed to be part of an Instrumentation
    /// packet, until `payload` contains `expected_size` bytes.
    Instrumentation {
        port: u8,
        payload: Vec<u8>,
        expected_size: usize,
    },

    /// Next bytes will be assumed to be part of a Hardware source
    /// packet, until `payload` contains `expected_size` bytes.
    HardwareSource {
        disc_id: u8,
        payload: Vec<u8>,
        expected_size: usize,
    },

    /// Next bytes will be assumed to be part of a LocalTimestamp{1,2}
    /// packet, until the MSB is set.
    LocalTimestamp {
        data_relation: TimestampDataRelation,
        payload: Vec<u8>,
    },

    /// Next bytes will be assumed to be part of a GlobalTimestamp1
    /// packet, until the MSB is set.
    GlobalTimestamp1 { payload: Vec<u8> },

    /// Next bytes will be assumed to be part of a GlobalTimestamp2
    /// packet, until the MSB is set.
    GlobalTimestamp2 { payload: Vec<u8> },
}

impl Decoder {
    pub fn new() -> Self {
        Decoder {
            incoming: BitVec::new(),
            state: DecoderState::Header,
        }
    }

    /// Push trace data into the decoder.
    pub fn push(&mut self, data: Vec<u8>) {
        // To optimize the performance in pull, we must reverse the
        // input bitstream and prepend it. This is a costly operation,
        // but is better done here than elsewhere.
        let mut bv = BitVec::<LocalBits, _>::from_vec(data);
        bv.reverse();
        bv.append(&mut self.incoming);
        self.incoming.append(&mut bv);
    }

    /// Pull the next decoded ITM packet from the decoder, if any and able.
    pub fn pull(&mut self) -> Result<Option<TracePacket>, DecoderError> {
        loop {
            match self.state {
                DecoderState::Syncing(_) => return self.handle_sync(),
                // Decode bytes until a packet is generated, or until we run out of bytes.
                _ if self.incoming.len() >= 8 => match {
                    let mut b: u8 = 0;
                    for i in 0..8 {
                        b |= (self.incoming.pop().unwrap() as u8) << i;
                    }

                    self.process_byte(b)
                } {
                    Ok(Some(packet)) => return Ok(Some(packet)),
                    Ok(None) => continue,
                    e => return e,
                },
                _ => return Ok(None),
            }
        }
    }

    /// Read zeros from the bitstream until the first bit is set. This
    /// realigns the incoming bitstream for further processing, which
    /// may not be 8-bit aligned.
    fn handle_sync(&mut self) -> Result<Option<TracePacket>, DecoderError> {
        const MIN_ZEROS: usize = 47;

        if let DecoderState::Syncing(mut count) = self.state {
            while let Some(bit) = self.incoming.pop() {
                if !bit && count < MIN_ZEROS {
                    count += 1;
                    continue;
                } else if bit && count >= MIN_ZEROS {
                    self.state = DecoderState::Header;
                    return Ok(Some(TracePacket::Sync));
                } else {
                    return Err(DecoderError::InvalidSyncSize(count));
                }
            }
        } else {
            unreachable!();
        }

        Ok(None)
    }

    /// Processes a single byte from the bitstream and changes decoder state if necessary.
    fn process_byte(&mut self, b: u8) -> Result<Option<TracePacket>, DecoderError> {
        let packet = match &mut self.state {
            DecoderState::Header => self.decode_header(b),
            DecoderState::Syncing(_count) => unreachable!(),
            DecoderState::HardwareSource {
                disc_id,
                payload,
                expected_size,
            } => {
                payload.push(b);
                if payload.len() == *expected_size {
                    match Decoder::handle_hardware_source(*disc_id, payload.to_vec()) {
                        Ok(packet) => Ok(Some(packet)),
                        Err(e) => Err(e),
                    }
                } else {
                    Ok(None)
                }
            }
            DecoderState::LocalTimestamp {
                data_relation,
                payload,
            } => {
                let last_byte = (b >> 7) & 1 == 0;
                payload.push(b);
                if last_byte {
                    Ok(Some(TracePacket::LocalTimestamp1 {
                        data_relation: data_relation.clone(),
                        ts: Decoder::extract_timestamp(payload.to_vec(), 27),
                    }))
                } else {
                    Ok(None)
                }
            }
            DecoderState::GlobalTimestamp1 { payload } => {
                let last_byte = (b >> 7) & 1 == 0;
                payload.push(b);
                if last_byte {
                    Ok(Some(TracePacket::GlobalTimestamp1 {
                        ts: Decoder::extract_timestamp(payload.to_vec(), 25),
                        clkch: (payload.last().unwrap() & (1 << 5)) >> 5 == 1,
                        wrap: (payload.last().unwrap() & (1 << 6)) >> 6 == 1,
                    }))
                } else {
                    Ok(None)
                }
            }
            DecoderState::GlobalTimestamp2 { payload } => {
                let last_byte = (b >> 7) & 1 == 0;
                payload.push(b);
                if last_byte {
                    Ok(Some(TracePacket::GlobalTimestamp2 {
                        ts: Decoder::extract_timestamp(
                            payload.to_vec(),
                            match payload.len() {
                                4 => 47 - 26, // 48 bit timestamp
                                6 => 63 - 26, // 64 bit timestamp
                                _ => {
                                    return Err(DecoderError::InvalidGTS2Size {
                                        payload: payload.to_vec(),
                                    })
                                }
                            },
                        ),
                    }))
                } else {
                    Ok(None)
                }
            }
            DecoderState::Instrumentation {
                port,
                payload,
                expected_size,
            } => {
                payload.push(b);
                if payload.len() == *expected_size {
                    Ok(Some(TracePacket::Instrumentation {
                        port: *port,
                        payload: payload.to_vec(),
                    }))
                } else {
                    Ok(None)
                }
            }
        };

        if let Ok(Some(_)) = packet {
            self.state = DecoderState::Header;
        }

        packet
    }

    // TODO template this for u32, u64?
    fn extract_timestamp(payload: Vec<u8>, max_len: u64) -> u64 {
        // Decode the first N - 1 payload bytes
        let (rtail, head) = payload.split_at(payload.len() - 1);
        let mut ts: u64 = 0;
        for (i, b) in rtail.iter().enumerate() {
            ts |= ((b & !(1 << 7)) as u64) // mask out continuation bit
                << (7 * i);
        }

        // Mask out the timestamp's MSBs and shift them into the final
        // value.
        let shift = 7 - (max_len % 7);
        let mask: u8 = 0xFFu8.wrapping_shl(shift.try_into().unwrap()) >> shift;
        ts | (((head[0] & mask) as u64) << (7 * rtail.len()))
    }

    /// Decodes the payload of a hardware source packet, if able.
    #[bitmatch]
    fn handle_hardware_source(disc_id: u8, payload: Vec<u8>) -> Result<TracePacket, DecoderError> {
        match disc_id {
            0 => {
                // event counter wrap

                if payload.len() != 1 {
                    return Err(DecoderError::InvalidHardwarePacket { disc_id, payload });
                }

                let b = payload[0];
                Ok(TracePacket::EventCounterWrap {
                    cyc: b & (1 << 5) != 0,
                    fold: b & (1 << 4) != 0,
                    lsu: b & (1 << 3) != 0,
                    sleep: b & (1 << 2) != 0,
                    exc: b & (1 << 1) != 0,
                    cpi: b & (1 << 0) != 0,
                })
            }
            1 => {
                // exception trace

                if payload.len() != 2 {
                    return Err(DecoderError::InvalidHardwarePacket { disc_id, payload });
                }

                let exception_number = ((payload[1] as u16 & 1) << 8) | payload[0] as u16;
                let function = (payload[1] >> 4) & 0b11;
                return Ok(TracePacket::ExceptionTrace {
                    exception: match exception_number {
                        1 => ExceptionType::Reset,
                        2 => ExceptionType::Nmi,
                        3 => ExceptionType::HardFault,
                        4 => ExceptionType::MemManage,
                        5 => ExceptionType::BusFault,
                        6 => ExceptionType::UsageFault,
                        11 => ExceptionType::SVCall,
                        12 => ExceptionType::DebugMonitor,
                        14 => ExceptionType::PendSV,
                        15 => ExceptionType::SysTick,
                        n if n >= 16 => ExceptionType::ExternalInterrupt(n as usize - 16),
                        _ => {
                            return Err(DecoderError::InvalidExceptionTrace {
                                exception: exception_number,
                                function,
                            })
                        }
                    },
                    action: match function {
                        0b01 => ExceptionAction::Entered,
                        0b10 => ExceptionAction::Exited,
                        0b11 => ExceptionAction::Returned,
                        _ => {
                            return Err(DecoderError::InvalidExceptionTrace {
                                exception: exception_number,
                                function,
                            })
                        }
                    },
                });
            }
            2 => {
                // PC sample
                match payload.len() {
                    1 if payload[0] == 0 => Ok(TracePacket::PCSample { pc: None }),
                    4 => Ok(TracePacket::PCSample {
                        pc: Some(u32::from_le_bytes(payload.try_into().unwrap())),
                    }),
                    _ => Err(DecoderError::InvalidPCSampleSize { payload }),
                }
            }
            8..=23 => {
                // data trace
                #[bitmatch]
                let "???t_tccd" = disc_id; // we have already masked out bit[2:0]
                let comparator = c;

                match (t, d, payload.len()) {
                    (0b01, 0, 4) => {
                        // PC value packet
                        Ok(TracePacket::DataTracePC {
                            comparator,
                            pc: u32::from_le_bytes(payload.try_into().unwrap()),
                        })
                    }
                    (0b01, 1, 2) => {
                        // address packet
                        Ok(TracePacket::DataTraceAddress {
                            comparator,
                            data: payload,
                        })
                    }
                    (0b10, d, _) => {
                        // data value packet
                        Ok(TracePacket::DataTraceValue {
                            comparator,
                            access_type: if d == 0 {
                                MemoryAccessType::Read
                            } else {
                                MemoryAccessType::Write
                            },
                            value: payload,
                        })
                    }
                    _ => Err(DecoderError::InvalidHardwarePacket { disc_id, payload }),
                }
            }
            _ => unreachable!(), // we already verify the discriminator when we decode the header
        }
    }

    /// Decodes the header byte of a packet, and enters the appropriate decoder state, if able.
    #[bitmatch]
    fn decode_header(&mut self, header: u8) -> Result<Option<TracePacket>, DecoderError> {
        fn translate_ss(ss: u8) -> Option<usize> {
            // See (Appendix D4.2.8, Table D4-4)
            Some(
                match ss {
                    0b01 => 2,
                    0b10 => 3,
                    0b11 => 5,
                    _ => return None,
                } - 1, // ss would include the header byte, but it has already been processed
            )
        }

        #[bitmatch]
        match header {
            // Synchronization packet category
            "0000_0000" => {
                self.state = DecoderState::Syncing(8);
            }

            // Protocol packet category
            "0111_0000" => {
                return Ok(Some(TracePacket::Overflow));
            }
            "11rr_0000" => {
                // Local timestamp, format 1 (LTS1)
                let tc = r; // relationship with corresponding data

                self.state = DecoderState::LocalTimestamp {
                    data_relation: match tc {
                        0b00 => TimestampDataRelation::Sync,
                        0b01 => TimestampDataRelation::UnknownDelay,
                        0b10 => TimestampDataRelation::AssocEventDelay,
                        0b11 => TimestampDataRelation::UnknownAssocEventDelay,
                        _ => unreachable!(),
                    },
                    payload: vec![],
                };
            }
            "0ttt_0000" => {
                // Local timestamp, format 2 (LTS2)
                return Ok(Some(TracePacket::LocalTimestamp2 { ts: t }));
            }
            "1001_0100" => {
                // Global timestamp, format 1 (GTS1)
                self.state = DecoderState::GlobalTimestamp1 { payload: vec![] };
            }
            "1011_0100" => {
                // Global timestamp, format 2(GTS2)
                self.state = DecoderState::GlobalTimestamp2 { payload: vec![] };
            }
            "0ppp_1000" => {
                // Extension packet
                return Ok(Some(TracePacket::Extension { page: p }));
            }

            // Source packet category
            "aaaa_a0ss" => {
                // Instrumentation packet
                self.state = DecoderState::Instrumentation {
                    port: a,
                    payload: vec![],
                    expected_size: if let Some(s) = translate_ss(s) {
                        s
                    } else {
                        return Err(DecoderError::InvalidSourcePayload { header, size: s });
                    },
                };
            }
            "aaaa_a1ss" => {
                // Hardware source packet
                let disc_id = a;

                if !(0..=2).contains(&disc_id) && !(8..=23).contains(&disc_id) {
                    return Err(DecoderError::InvalidHardwareDisc {
                        disc_id,
                        size: s.into(),
                    });
                }

                self.state = DecoderState::HardwareSource {
                    disc_id,
                    payload: vec![],
                    expected_size: if let Some(s) = translate_ss(s) {
                        s
                    } else {
                        return Err(DecoderError::InvalidSourcePayload { header, size: s });
                    },
                };
            }
            "hhhh_hhhh" => return Err(DecoderError::InvalidHeader(h)),
        }

        Ok(None)
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_sync_packet() {
        let mut trace_data: Vec<u8> = [0; 47 / 8].to_vec();
        trace_data.push(1 << 7);

        let mut decoder = Decoder::new();
        decoder.push(trace_data);
        assert_eq!(decoder.pull(), Ok(Some(TracePacket::Sync)));
    }

    #[test]
    fn decode_overflow_packet() {
        let mut decoder = Decoder::new();
        decoder.push([0b0111_0000].to_vec());
        assert_eq!(decoder.pull(), Ok(Some(TracePacket::Overflow)));
    }

    #[test]
    fn decode_local_timestamp_packets() {
        let mut decoder = Decoder::new();
        #[rustfmt::skip]
        decoder.push([
            // LTS1
            0b1100_0000,
            0b1100_1001,
            0b0000_0001,

            // LTS2
            0b0101_0000,
        ].to_vec());

        for packet in [
            TracePacket::LocalTimestamp1 {
                ts: 0b11001001,
                data_relation: TimestampDataRelation::Sync,
            },
            TracePacket::LocalTimestamp2 { ts: 0b101 },
        ]
        .iter()
        {
            assert_eq!(decoder.pull(), Ok(Some(packet.clone())));
        }
    }

    #[test]
    fn extract_timestamp() {
        #[rustfmt::skip]
        let ts: Vec<u8> = [
            0b1000_0000,
            0b1000_0000,
            0b1000_0000,
            0b0000_0000,
        ].to_vec();

        assert_eq!(Decoder::extract_timestamp(ts, 25), 0);

        #[rustfmt::skip]
        let ts: Vec<u8> = [
            0b1000_0001,
            0b1000_0111,
            0b1001_1111,
            0b0111_1111
        ].to_vec();

        assert_eq!(
            Decoder::extract_timestamp(ts, 27),
            0b1111111_0011111_0000111_0000001,
        );

        #[rustfmt::skip]
        let ts: Vec<u8> = [
            0b1000_0001,
            0b1000_0111,
            0b1001_1111,
            0b1111_1111
        ].to_vec();

        assert_eq!(
            Decoder::extract_timestamp(ts, 25),
            0b11111_0011111_0000111_0000001,
        );
    }

    #[test]
    fn decode_global_timestamp_packets() {
        let mut decoder = Decoder::new();
        #[rustfmt::skip]
        decoder.push([
            // GTS1
            0b1001_0100,
            0b1000_0000,
            0b1010_0000,
            0b1000_0100,
            0b0110_0000,

            // GTS2 (48-bit)
            0b1011_0100,
            0b1011_1101,
            0b1111_0100,
            0b1001_0001,
            0b0000_0001,

            // GTS2 (64-bit)
            0b1011_0100,
            0b1011_1101,
            0b1111_0100,
            0b1001_0001,
            0b1000_0001,
            0b1111_0100,
            0b0000_0111,
        ].to_vec());

        for packet in [
            TracePacket::GlobalTimestamp1 {
                ts: 0b00000_0000100_0100000_0000000,
                wrap: true,
                clkch: true,
            },
            TracePacket::GlobalTimestamp2 {
                ts: 0b1_0010001_1110100_0111101,
            },
            TracePacket::GlobalTimestamp2 {
                ts: 0b111_1110100_0000001_0010001_1110100_0111101,
            },
        ]
        .iter()
        {
            assert_eq!(decoder.pull(), Ok(Some(packet.clone())));
        }
    }

    #[test]
    fn decode_extention_packet() {
        let mut decoder = Decoder::new();
        #[rustfmt::skip]
        decoder.push([
            0b0111_1000,
        ].to_vec());

        assert_eq!(
            decoder.pull(),
            Ok(Some(TracePacket::Extension { page: 0b111 }))
        );
    }

    #[test]
    fn decode_instrumentation_packet() {
        let mut decoder = Decoder::new();
        #[rustfmt::skip]
        decoder.push([
            0b1000_1011,
            0b0000_0011,
            0b0000_1111,
            0b0011_1111,
            0b1111_1111,
        ].to_vec());

        assert_eq!(
            decoder.pull(),
            Ok(Some(TracePacket::Instrumentation {
                port: 0b1000_1,
                #[rustfmt::skip]
                payload: [
                    0b0000_0011,
                    0b0000_1111,
                    0b0011_1111,
                    0b1111_1111,
                ].to_vec(),
            }))
        );
    }

    #[test]
    fn decode_eventcounterwrap_packet() {
        let mut decoder = Decoder::new();
        #[rustfmt::skip]
        decoder.push([
            0b0000_0101,
            0b0010_1010,
        ].to_vec());

        assert_eq!(
            decoder.pull(),
            Ok(Some(TracePacket::EventCounterWrap {
                cyc: true,
                fold: false,
                lsu: true,
                sleep: false,
                exc: true,
                cpi: false,
            }))
        );
    }

    #[test]
    fn decode_exceptiontrace_packet() {
        let mut decoder = Decoder::new();
        #[rustfmt::skip]
        decoder.push([
            0b0000_1110,
            0b0010_0000,
            0b0011_0000
        ].to_vec());

        assert_eq!(
            decoder.pull(),
            Ok(Some(TracePacket::ExceptionTrace {
                exception: ExceptionType::ExternalInterrupt(16),
                action: ExceptionAction::Returned,
            }))
        );
    }

    #[test]
    fn decode_pcsample_packet() {
        let mut decoder = Decoder::new();
        #[rustfmt::skip]
        decoder.push([
            // PC sample (not sleeping)
            0b0001_0111,
            0b0000_0011,
            0b0000_1111,
            0b0011_1111,
            0b1111_1111,

            // PC sample (sleeping)
            0b0001_0101,
            0b0000_0000,
        ].to_vec());

        for packet in [
            TracePacket::PCSample {
                pc: Some(0b11111111_00111111_00001111_00000011),
            },
            TracePacket::PCSample { pc: None },
        ]
        .iter()
        {
            assert_eq!(decoder.pull(), Ok(Some(packet.clone())));
        }
    }

    #[test]
    fn decode_datatracepc_packet() {
        let mut decoder = Decoder::new();
        #[rustfmt::skip]
        decoder.push([
            0b0111_0111,
            0b0000_0011,
            0b0000_1111,
            0b0011_1111,
            0b1111_1111,
        ].to_vec());

        assert_eq!(
            decoder.pull(),
            Ok(Some(TracePacket::DataTracePC {
                comparator: 0b11,
                pc: 0b11111111_00111111_00001111_00000011,
            }))
        );
    }

    #[test]
    fn decode_datatraceaddress_packet() {
        let mut decoder = Decoder::new();
        #[rustfmt::skip]
        decoder.push([
            0b0110_1110,
            0b0000_0011,
            0b0000_1111,
        ].to_vec());

        assert_eq!(
            decoder.pull(),
            Ok(Some(TracePacket::DataTraceAddress {
                comparator: 0b10,
                #[rustfmt::skip]
                data: [
                    0b0000_0011,
                    0b0000_1111,
                ].to_vec(),
            }))
        );
    }

    #[test]
    fn decode_datatracevalue_packet() {
        let mut decoder = Decoder::new();
        #[rustfmt::skip]
        decoder.push([
            // four-byte (word) payload
            0b1010_1111,
            0b0000_0011,
            0b0000_1111,
            0b0011_1111,
            0b1111_1111,

            // two-byte (halfword) payload
            0b1010_1110,
            0b0000_0011,
            0b0000_1111,

            // one-byte (byte) payload
            0b1010_1101,
            0b0000_0011,
        ].to_vec());

        for packet in [
            TracePacket::DataTraceValue {
                comparator: 0b10,
                access_type: MemoryAccessType::Write,
                #[rustfmt::skip]
                value: [
                    0b0000_0011,
                    0b0000_1111,
                    0b0011_1111,
                    0b1111_1111,
                ].to_vec(),
            },
            TracePacket::DataTraceValue {
                comparator: 0b10,
                access_type: MemoryAccessType::Write,
                #[rustfmt::skip]
                value: [
                    0b0000_0011,
                    0b0000_1111,
                ].to_vec(),
            },
            TracePacket::DataTraceValue {
                comparator: 0b10,
                access_type: MemoryAccessType::Write,
                #[rustfmt::skip]
                value: [
                    0b0000_0011,
                ].to_vec(),
            },
        ]
        .iter()
        {
            assert_eq!(decoder.pull(), Ok(Some(packet.clone())));
        }
    }
}
