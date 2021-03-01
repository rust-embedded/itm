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
    Header(HeaderError),
    Payload(PayloadError),
}

/// Upon this error, decoder should still be in header mode
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderError {
    Invalid(u8),
    HardwareDisc {
        disc_id: u8,
        size: usize,
    },

    /// Invalid payload size
    InstumentationSize {
        port: u8,

        /// including the header byte
        expected_size: usize,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum PayloadError {
    GTS2(usize),

    /// either exception number or action is invalid
    ExceptionTrace(u16, u8),

    PCSample(Vec<u8>),
    Exception(Vec<u8>),
    DataTrace(u8, Vec<u8>),
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

    /// Pull the next item from the decoder.
    pub fn pull(&mut self) -> Result<Option<TracePacket>, DecoderError> {
        // Decode bytes until a packet is generated, or until we run out
        // of bytes.
        while self.incoming.len() >= 8 {
            // XXX do we copy anything here?
            let b = self.incoming[0..=7].load::<u8>();
            self.incoming = self.incoming[8..].into();

            match self.process_byte(b) {
                Ok(Some(packet)) => return Ok(Some(packet)),
                Ok(None) => continue,
                Err(e) => {
                    match e {
                        DecoderError::Header(_) => assert!(self.state == DecoderState::Header),
                        DecoderError::Payload(_) => {}
                    }
                    return Err(e);
                }
            }
        }

        Ok(None)
    }

    fn process_byte(&mut self, b: u8) -> Result<Option<TracePacket>, DecoderError> {
        let packet = match &mut self.state {
            DecoderState::Header => self.decode_header(b),
            DecoderState::Syncing(count) => {
                // This packet is at least comprised of 47 zeroes but
                // mustn't be a multiple of 8 bits. If the first set
                // bit, that denotes end-of-packet, is not in the 7th
                // position, ...
                // for i in 0..8 {
                //     if b & (1 << i) {
                //         // put back 7 - i bits at head of stream.
                //     }
                // }

                // TODO check that packet contains at least 47 zeroes.
                // TODO do we need to change to bitvec? Or can we keep
                // use of a standard Vec<u8>? If we use the former:
                // - added dep
                // - some overhead to restructure already written code
                // - changed public API?
                // + very easy to handle a sync (we need just push the bits back)
                //
                // the latter:
                //
                // - difficult sync (up to seven bits in the bitstream's
                // last byte would be "missing". We would have to keep
                // tabs on the current alignment in feed(), and appropriately shift any new bytes into the last byte of those incoming (that is, after shifting all incoming first)).

                // For now, just handle smallest possible sync packet
                if b == 0 && *count < (47 as usize) {
                    *count += 8;
                    Ok(None)
                } else if b == 0b1000_0000 {
                    *count += 7;
                    assert!(*count == (47 as usize));
                    Ok(Some(TracePacket::Sync))
                } else {
                    todo!();
                }
            }
            DecoderState::HardwareSource {
                disc_id,
                payload,
                expected_size,
            } => {
                payload.push(b);
                if payload.len() == *expected_size {
                    match Decoder::handle_hardware_source(*disc_id, payload.to_vec()) {
                        Ok(packet) => Ok(Some(packet)),
                        Err(e) => {
                            self.state = DecoderState::Header;
                            Err(DecoderError::Payload(e))
                        }
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
                                n => return Err(DecoderError::Payload(PayloadError::GTS2(n))),
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
    fn handle_hardware_source(disc_id: u8, payload: Vec<u8>) -> Result<TracePacket, PayloadError> {
        match disc_id {
            0 => {
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
                    return Err(PayloadError::Exception(payload));
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
                        _ => return Err(PayloadError::ExceptionTrace(exception_number, function)),
                    },
                    action: match function {
                        0b01 => ExceptionAction::Entered,
                        0b10 => ExceptionAction::Exited,
                        0b11 => ExceptionAction::Returned,
                        _ => return Err(PayloadError::ExceptionTrace(exception_number, function)),
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
                    _ => Err(PayloadError::PCSample(payload)),
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
                    _ => Err(PayloadError::DataTrace(disc_id, payload)),
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
                            return Err(DecoderError::Header(HeaderError::InstumentationSize {
                                port: a,
                                expected_size: s.into(),
                            }))
                        }
                    } - 1, // header byte already processed
                };
            }
            "aaaa_a1ss" => {
                // Hardware source packet
                let disc_id = a;

                if !(0..=2).contains(&disc_id) && !(8..=23).contains(&disc_id) {
                    return Err(DecoderError::Header(HeaderError::HardwareDisc {
                        disc_id,
                        size: s.into(),
                    }));
                }

                self.state = DecoderState::HardwareSource {
                    disc_id,
                    payload: vec![],
                    expected_size: s.into(),
                };
            }
            "hhhh_hhhh" => return Err(DecoderError::Header(HeaderError::Invalid(h))),
        }

        Ok(None)
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
