//! Refer to appendix D4 in the ARMv7-M architecture reference manual.

use bitmatch::bitmatch;
use bitvec::prelude::*;
use std::convert::TryInto;

/// The set of possible packet types that may be decoded.
///
/// (armv7m) would suggest an implementation of two enum types
#[derive(Debug, Clone, PartialEq)]
pub enum TracePacket {
    // Synchronization packet category (Appendix D4, p. 782)
    /// A synchronization packet is a unique pattern in the bitstream.
    /// It is identified and used to provide the alignment of other
    /// packet bytes in the bitstream. (armv7m, Appendix D4.2.1)
    Sync,

    // Protocol packet category (Appendix D4, p. 782)
    /// Found in the bitstream if
    ///
    /// - Software has written to an ITM stimulus port register when the
    /// stimulus port output buffer is full.
    ///
    /// - The DWT attempts to generate a hardware source packet when the
    /// DWT output buffer is full.
    ///
    /// - The local timestamp counter overflows.
    ///
    /// See (armv7m, Appendix D4.2.3).
    Overflow,

    /// A delta timestamp that measures the interval since the
    /// generation of the last local timestamp and its relation to the
    /// corresponding ITM/DWT data packets. (armv7m, Appendix D4.2.4)
    LocalTimestamp1 {
        /// Timestamp value.
        ts: u32,

        /// Indicates the relationship between the generation of `ts`
        /// and the corresponding ITM or DWT data packet.
        data_relation: TimestampDataRelation,
    },

    /// A smaller-interval delta timestamp that measures the interval
    /// since the generation of the last local timestamp which is
    /// synchronous with corresponding ITM/DWT data packets. (armv7m,
    /// Appendix D4.2.4)
    LocalTimestamp2 {
        /// Timestamp value.
        ts: u8, // must not be 0b000 or 0b111
    },

    /// An absolute timestamp based on the global timestamp clock that
    /// contain the lower-order bits. (armv7m, Appendix D4.2.5)
    GlobalTimestamp1 {
        /// Timestamp value.
        ts: usize,

        /// Set if higher order bits output by the last GTS2 have
        /// changed.
        wrap: bool,

        /// Set if the system has asserted a clock change input to the
        /// processor since the last generated global timestamp.
        clkch: bool,
    },

    /// An absolute timestamp based on the global timestamp clock that
    /// contain the higher-order bits. (armv7m, Appendix D4.2.5)
    GlobalTimestamp2 {
        /// Timestamp value.
        ts: usize,
    },

    /// A packet that provides additional information about the
    /// identified source (one of two possible, theoretically). On
    /// ARMv7-M this packet is only used to denote on which ITM stimulus
    /// port a payload was written. (armv7m, Appendix D4.2.6)
    Extension {
        /// Source port page number
        page: u8,
    },

    // Source packet category
    /// Contains the payload written to the ITM stimulus ports.
    Instrumentation {
        /// Stimulus port number.
        port: u8,

        /// Instrumentation data written to the stimulus port.
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

    /// Periodic program counter sample. (Appendix D4.3.3)
    PCSample {
        /// `None` if periodic PC sleep packet.
        pc: Option<u32>,
    },

    /// A DWT comparator matched a program counter (PC) value. (Appendix
    /// D4.3.4)
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

        /// Address content.
        address: u16,
    },

    DataTraceValue {
        /// The comparator number that generated the data.
        comparator: u8,
        access_type: MemoryAccessType,
        value: Vec<u8>,
    },
}

/// Denotes the exception action taken by the processor. (Table D4-6)
#[derive(Debug, Clone, PartialEq)]
pub enum ExceptionAction {
    Entered,
    Exited,
    Returned,
}

/// Denotes the exception type (interrupt event) of the processor.
/// (Table B1-4)
#[derive(Debug, Clone, PartialEq)]
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

/// This enum denotes the type of memory access.
#[derive(Debug, Clone, PartialEq)]
pub enum MemoryAccessType {
    Read,
    Write,
}

/// Indicates the relationship between the generation of the local
/// timestamp packet and the corresponding ITM or DWT data packet.
#[derive(Debug, Clone, PartialEq)]
pub enum TimestampDataRelation {
    /// The local timestamp value is synchronous to the corresponding
    /// ITM or DWT data. The value in the TS field is the timestamp
    /// counter value when the ITM or DWT packet is generated.
    Synced,

    /// The local timestamp value is delayed relative to the ITM or DWT
    /// data. The value in the TS field is the timestamp counter value
    /// when the Local timestamp packet is generated.
    ///
    /// Note: the local timestamp value corresponding to the previous
    /// ITM or DWT packet is unknown, but must be between the previous
    /// and the current local timestamp values.
    Delayed,

    /// Output of the ITM or DWT packet corresponding to this Local
    /// timestamp packet is delayed relative to the associated event.
    /// The value in the TS field is the timestamp counter value when
    /// the ITM or DWT packets is generated.
    ///
    /// This encoding indicates that the ITM or DWT packet was delayed
    /// relative to other trace output packets.
    DelayedRelative, // TODO improve name

    /// Output of the ITM or DWT packet corresponding to this Local
    /// timestamp packet is delayed relative to the associated event,
    /// and this Local timestamp packet is delayed relative to the ITM
    /// or DWT data. This is a combined condition of `Delayed` and
    /// `DelayedRelative`.
    DelayedRelativeRelative, // TODO improve name
}

#[derive(Debug, Clone, PartialEq)]
pub enum DecoderError {
    /// Header is invalid and cannot be decoded.
    InvalidHeader(u8),

    /// The type discriminator ID in the hardware source packet header
    /// is invalid or the associated payload is of wrong size.
    InvalidHardwarePacket {
        /// The discriminator ID. Potentially invalid.
        disc_id: u8,

        /// Associated payload. Potentially invalid length. Empty if
        /// `disc_id` is invalid.
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

    /// The expected payload size of an Instrumentation packet is invalid.
    InvalidInstumentationSize {
        /// The port from which the instrumentation packet is sourced.
        port: u8,

        /// The invalid expected payload size.
        expected_size: usize,
    },

    /// An exception trace packet refers to an invalid action or an
    /// invalid exception number.
    InvalidExceptionTrace { exception: u16, function: u8 },

    /// The payload length of a PCSample packet is invalid.
    InvalidPCSampleSize {
        /// The payload constituting the PC value, of invalid size.
        payload: Vec<u8>,
    },

    /// The GlobalTimestamp2 packet does not contain a 48-bit or 64-bit timestamp.
    InvalidGTS2Size {
        /// The payload constituting the timestamp, of invalid size.
        payload: Vec<u8>,
    },

    /// The number of zeroes in the Synchronization packet is less than
    /// 47. The decoder is now in an unknown state; manual intervention
    /// required.
    InvalidSyncSize(usize),
}

/// Trace data decoder.
///
/// This is a sans-io style decoder.
/// See also: https://sans-io.readthedocs.io/how-to-sans-io.html
pub struct Decoder {
    /// public because manual intervention may be necessary
    pub incoming: BitVec,

    /// public because manual intervention may be necessary
    pub state: DecoderState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DecoderState {
    Header,
    Syncing(usize),
    Instrumentation {
        port: u8,
        payload: Vec<u8>,
        expected_size: usize,
    },
    HardwareSource {
        disc_id: u8,
        payload: Vec<u8>,
        expected_size: usize,
    },
    LocalTimestamp {
        data_relation: TimestampDataRelation,
        payload: Vec<u8>,
    },
    GlobalTimestamp1 {
        payload: Vec<u8>,
    },
    GlobalTimestamp2 {
        payload: Vec<u8>,
    },
}

impl Decoder {
    pub fn new() -> Self {
        Decoder {
            incoming: BitVec::new(),
            state: DecoderState::Header,
        }
    }

    /// Feed trace data into the decoder.
    pub fn feed(&mut self, data: Vec<u8>) {
        self.incoming.extend(BitVec::<LocalBits, _>::from_vec(data));
    }

    /// Pull the next decoded ITM packet from the decoder, if any.
    pub fn pull(&mut self) -> Result<Option<TracePacket>, DecoderError> {
        // Decode bytes until a packet is generated, or until we run out of bytes.
        while self.incoming.len() >= 8 {
            if let DecoderState::Syncing(_) = self.state {
                break;
            }

            // XXX do we copy anything here?
            let b = self.incoming[0..=7].load::<u8>();
            self.incoming = self.incoming[8..].into();

            match self.process_byte(b) {
                Ok(Some(packet)) => return Ok(Some(packet)),
                Ok(None) => continue,
                Err(e) => {
                    self.state = DecoderState::Header;
                    return Err(e);
                },
            }
        }

        if let DecoderState::Syncing(mut count) = self.state {
            while self.incoming.len() > 0 {
                let bit = self.incoming[0];
                self.incoming = self.incoming[1..].into();

                if !bit && count < (47 as usize) {
                    count += 1;
                    continue;
                } else if bit && count >= (47 as usize) {
                    self.state = DecoderState::Header;
                    return Ok(Some(TracePacket::Sync));
                } else {
                    return Err(DecoderError::InvalidSyncSize(count));
                }
            }

            return Ok(None);
        }

        Ok(None)
    }

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
                        ts: Decoder::extract_timestamp(payload.to_vec(), 25) as usize,
                        clkch: payload.last().unwrap() & (1 << 5) == 1,
                        wrap: payload.last().unwrap() & (1 << 6) == 1,
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
                        ) as usize,
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

    fn extract_timestamp(payload: Vec<u8>, max_len: u32) -> u32 {
        // Decode the first N - 1 payload bytes
        let (rtail, head) = payload.split_at(payload.len() - 1);
        let mut ts: u32 = 0;
        for (i, b) in rtail.iter().enumerate() {
            ts |= ((b & !(1 << 7)) as u32) // mask out continuation bit
                << (7 * i);
        }

        // Mask out the timestamp's MSBs and shift them into the final
        // value.
        let mask = !(1 << ((max_len % 7) + 2));
        ts | ((head[0] as u32 & mask) << (7 * rtail.len()))
    }

    #[bitmatch]
    fn handle_hardware_source(disc_id: u8, payload: Vec<u8>) -> Result<TracePacket, DecoderError> {
        match disc_id {
            0 => {
                if payload.len() != 1 {
                    return Err(DecoderError::InvalidHardwarePacket { disc_id, payload });
                }
                // event counter wrapping
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
                // PC sampling
                match payload.len() {
                    1 if payload[0] == 0 => Ok(TracePacket::PCSample { pc: None }),
                    4 => Ok(TracePacket::PCSample {
                        pc: Some(u32::from_le_bytes(payload.try_into().unwrap())),
                    }),
                    _ => Err(DecoderError::InvalidPCSampleSize { payload }),
                }
            }
            8..=23 => {
                // data tracing
                #[bitmatch]
                let "???t_tccd" = disc_id; // we have masked out bit[2:0]
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
                            address: u16::from_le_bytes(payload.try_into().unwrap()),
                        })
                    }
                    (0b10, d, _) => {
                        // data value packet, read access
                        Ok(TracePacket::DataTraceValue {
                            comparator,
                            access_type: if d == 0 {
                                MemoryAccessType::Write
                            } else {
                                MemoryAccessType::Read
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

    #[bitmatch]
    fn decode_header(&mut self, header: u8) -> Result<Option<TracePacket>, DecoderError> {
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
                // LTS1
                let tc = r; // relationship with corresponding data

                self.state = DecoderState::LocalTimestamp {
                    data_relation: match tc {
                        0b00 => TimestampDataRelation::Synced,
                        0b01 => TimestampDataRelation::Delayed,
                        0b10 => TimestampDataRelation::DelayedRelative,
                        0b11 => TimestampDataRelation::DelayedRelativeRelative,
                        _ => unreachable!(),
                    },
                    payload: vec![],
                };
            }
            "0ttt_0000" => {
                // LTS2
                return Ok(Some(TracePacket::LocalTimestamp2 { ts: t }));
            }
            "1001_0100" => {
                // GTS1
                self.state = DecoderState::GlobalTimestamp1 { payload: vec![] };
            }
            "1011_0100" => {
                // GTS2
                self.state = DecoderState::GlobalTimestamp2 { payload: vec![] };
            }
            "0ppp_1000" => {
                // Extension
                return Ok(Some(TracePacket::Extension { page: p }));
            }

            // Source packet category
            "aaaa_a0ss" => {
                // Instrumentation packet
                self.state = DecoderState::Instrumentation {
                    port: a,
                    payload: vec![],
                    expected_size: match s {
                        0b01 => 2,
                        0b10 => 3,
                        0b11 => 5,
                        _ => {
                            return Err(DecoderError::InvalidInstumentationSize {
                                port: a,
                                expected_size: s.into(),
                            })
                        }
                    } - 1, // header byte already processed
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
                    expected_size: s.into(),
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
