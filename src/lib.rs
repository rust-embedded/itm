//! This code was initially written by https://github.com/windelbouwman.
//! It was moved to the probe-rs project in accordance with him.
//!
//! Additions and fixes have been made thereafter.
//!
//! Trace protocol for the SWO pin.
//!
//! Refer to appendix D4 in the ARMv7-M architecture reference manual.
//! Also a good reference is itmdump.c from openocd:
//! https://github.com/arduino/OpenOCD/blob/master/contrib/itmdump.c
#![allow(dead_code)]
#![allow(unused_imports)]

use bitmatch::bitmatch;
use scroll::Pread;
use std::collections::VecDeque;

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
    ///
    /// TODO: change this to the type only armv7 uses?
    Extension {
        /// Information source bit.
        sh: bool,

        /// Extension information.
        ex: usize,
    },

    // Source packet category
    /// Contains the payload written to the ITM stimulus ports.
    Instrumentation {
        /// Stimulus port number.
        port: usize,

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
    PCSample { pc: u32 },

    /// A DWT comparator matched a program counter (PC) value. (Appendix
    /// D4.3.4)
    DataTracePC {
        /// The comparator number that generated the data.
        id: usize,

        /// The PC value for the instruction that caused the successful
        /// address comparison.
        pc: u32,
    },

    /// A DWT comparator matched an address. (Appendix D4.3.4)
    DataTraceAddress {
        /// The comparator number that generated the data.
        id: usize,

        /// Address content.
        address: u16,
    },

    DataTraceValue {
        /// The comparator number that generated the data.
        id: usize,
        access_type: MemoryAccessType,
        value: u32,
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

/// Trace data decoder.
///
/// This is a sans-io style decoder.
/// See also: https://sans-io.readthedocs.io/how-to-sans-io.html
pub struct Decoder {
    incoming: VecDeque<u8>,
    packets: VecDeque<TracePacket>,
    state: DecoderState,
}

enum DecoderState {
    Header,
    Syncing(usize),
    ItmData {
        id: usize,
        payload: Vec<u8>,
        size: usize,
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
}

impl Decoder {
    pub fn new() -> Self {
        Decoder {
            incoming: VecDeque::new(),
            packets: VecDeque::new(),
            state: DecoderState::Header,
        }
    }

    /// Feed trace data into the decoder.
    pub fn feed(&mut self, data: Vec<u8>) {
        self.incoming.extend(&data)
    }

    fn next_byte(&mut self) -> Option<u8> {
        self.incoming.pop_front()
    }

    /// Pull the next item from the decoder.
    pub fn pull(&mut self) -> Option<TracePacket> {
        // Process any bytes:
        self.process_incoming(); // reads all bytes in incoming, puts TracePackets in packets
        self.packets.pop_front() // pops the latest TracePacket to the API user
    }

    fn process_incoming(&mut self) {
        while let Some(b) = self.next_byte() {
            self.process_byte(b);
        }
    }

    fn process_byte(&mut self, b: u8) {
        // let Maybe(packet) = match self.state ...
        // self.emit(packet)
        // self.state = header

        match &mut self.state {
            DecoderState::Header => {
                self.decode_header(b);
            }
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
                } else if b == 0b1000_0000 {
                    *count += 7;
                    assert!(*count == (47 as usize));
                    self.emit(TracePacket::Sync);
                    self.state = DecoderState::Header;
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
                    let packet = Decoder::handle_hardware_source(*disc_id, payload.to_vec());
                    self.emit(packet);
                    self.state = DecoderState::Header;
                }
            }
            DecoderState::LocalTimestamp {
                data_relation,
                payload,
            } => {
                let last_byte = (b >> 7) & 1 == 0;
                payload.push(b);
                if last_byte {
                    let packet =
                        Decoder::handle_local_timestamp(data_relation.clone(), payload.to_vec());
                    self.emit(packet);
                    self.state = DecoderState::Header;
                }
            }
            _ => {
                todo!();
            }
        }
    }

    fn handle_local_timestamp(
        data_relation: TimestampDataRelation,
        payload: Vec<u8>,
    ) -> TracePacket {
        let mut ts: u32 = 0;
        for (i, b) in payload.iter().enumerate() {
            ts |= ((b & !(1 << 7)) as u32) // mask out continuation bit
                << (7 * i);
        }

        TracePacket::LocalTimestamp1 { data_relation, ts }
    }

    fn handle_hardware_source(disc_id: u8, payload: Vec<u8>) -> TracePacket {
        match disc_id {
            0 => {
                // event counter wrapping
                todo!();
            }
            1 => {
                let exception_number = ((payload[1] as u16 & 1) << 8) | payload[0] as u16;
                let function = (payload[1] >> 4) & 0b11;
                return TracePacket::ExceptionTrace {
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
                        _ => unimplemented!(
                            "invalid exception number {}. Payload is [{:b}, {:b}]",
                            exception_number,
                            payload[0],
                            payload[1]
                        ),
                    },
                    action: match function {
                        0b01 => ExceptionAction::Entered,
                        0b10 => ExceptionAction::Exited,
                        0b11 => ExceptionAction::Returned,
                        _ => unimplemented!(),
                    },
                };
            }
            2 => {
                // PC sampling
                todo!();
            }
            8..=23 => {
                // data tracing
                todo!();
            }
            _ => unreachable!(),
        }
    }

    fn emit(&mut self, packet: TracePacket) {
        self.packets.push_back(packet);
    }

    #[bitmatch]
    fn decode_header(&mut self, header: u8) {
        #[bitmatch]
        match header {
            // Synchronization packet category
            "0000_0000" => {
                self.state = DecoderState::Syncing(8);
            }

            // Protocol packet category
            "0111_0000" => {
                self.emit(TracePacket::Overflow);
                todo!();
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
                self.emit(TracePacket::LocalTimestamp2 { ts: t })
            }
            "1001_0100" => {
                // GTS1
                todo!();
            }
            "1011_0100" => {
                // GTS2
                todo!();
            }
            "ceee_1s00" => {
                // Extension
                let _c = c; // continuation bit
                let _ex = e; // extension information ex[2:0]
                let _sh = s; // information source bit

                todo!();
            }

            // Source packet category
            "aaaa_a0ss" => {
                // Instrumentation packet
                let _a = a; // the port number
                let _s = s; // payload size

                todo!();
            }
            "aaaa_a1ss" => {
                // Hardware source packet
                let disc_id = a;

                if !(0..=2).contains(&disc_id) && !(8..=23).contains(&disc_id) {
                    unimplemented!("undefined discriminator ID {}", disc_id);
                }

                self.state = DecoderState::HardwareSource {
                    disc_id,
                    payload: vec![],
                    expected_size: s.into(),
                };
            }
            "hhhh_hhhh" => {
                unimplemented!("Cannot process unknown header {:b}", h);
            }
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
