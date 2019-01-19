//! Defines ITM packets and their possible contents.

pub(crate) const MAX_PAYLOAD_SIZE: usize = 4;

/// Represents a complete received packet.
#[derive(Debug)]
pub struct Packet {
    /// The header byte received for this packet.
    pub(crate) header: u8,

    /// The kind (type) of this packet.
    pub(crate) kind: Kind,
}

impl Packet {
    /// Returns the header byte received for this packet.
    pub fn header(&self) -> u8 {
        self.header
    }

    /// The kind (type) of this packet.
    pub fn kind(&self) -> &Kind {
        &self.kind
    }
}

/// The type of a packet.
#[derive(Debug)]
pub enum Kind {
    /// Synchronization packet
    Synchronization(Synchronization),

    /// Overflow packet
    Overflow,

    /// Exception trace
    ExceptionTrace(ExceptionTrace),

    /// Data from a software application
    Instrumentation(Instrumentation),

    /// Local timestamp
    LocalTimestamp(LocalTimestamp),

    /// Extension packet for the stimulus port page number
    ExtensionStimulusPortPage(ExtensionStimulusPortPage),

    /// Event counter
    EventCounter(EventCounter),

    /// Periodic PC sample
    PeriodicPcSample(PeriodicPcSample),

    /// Data trace PC value
    DataTracePcValue(DataTracePcValue),

    /// Data trace address
    DataTraceAddress(DataTraceAddress),

    /// Data trace data value
    DataTraceDataValue(DataTraceDataValue),

    #[doc(hidden)]
    /// External consumers shouldn't expect the public variants to
    /// be complete: there are more variants to implement.
    _NoExhaustiveMatch,
}

/// Synchronization packet
#[derive(Debug)]
pub struct Synchronization {
    pub(crate) bytes: u8,
}

impl Synchronization {
    /// Number of synchronization bytes
    pub fn bytes(&self) -> u8 {
        self.bytes
    }
}

/// Exception trace packet
#[derive(Clone, Debug)]
pub struct ExceptionTrace {
    pub(crate) number: u16,
    pub(crate) function: Function,
}

impl ExceptionTrace {
    /// Exception number
    pub fn number(&self) -> u16 {
        self.number
    }

    /// The action taken by the processor
    pub fn function(&self) -> Function {
        self.function
    }
}

/// The action taken by the processor
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Function {
    /// Entered exception
    Enter,
    /// Exited exception
    Exit,
    /// Returned to exception
    Return,
}

/// Contents of an Instrumentation packet, with data from a software application
#[derive(Debug)]
pub struct Instrumentation {
    /// Contains the data in this packet.
    pub(crate) payload: [u8; MAX_PAYLOAD_SIZE],

    /// The length of `payload` that contains the relevant data.
    pub(crate) payload_len: usize,

    /// Stimulus port this packet was sent from.
    pub(crate) port: u8,
}

impl Instrumentation {
    /// Data in this packet.
    pub fn payload(&self) -> &[u8] {
        &self.payload[0..self.payload_len]
    }

    /// Stimulus port this packet was sent from.
    pub fn port(&self) -> u8 {
        self.port
    }
}

/// Local timestamp packet
#[derive(Debug)]
pub struct LocalTimestamp {
    pub(crate) delta: u32,
    // TC[1:0] bits
    pub(crate) tc: u8,
}

impl LocalTimestamp {
    /// The local timestamp value
    ///
    /// This is the interval since the previous Local timestamp packet
    pub fn delta(&self) -> u32 {
        self.delta
    }

    /// The local timestamp value is synchronous to the corresponding ITM or DWT data.
    ///
    /// The value in the TS field is the timestamp counter value when the ITM or DWT packet is
    /// generated.
    pub fn is_precise(&self) -> bool {
        self.tc == 0
    }

    /// The local timestamp value is delayed relative to the ITM or DWT data.
    ///
    /// The value in the TS field is the timestamp counter value when the Local timestamp packet is
    /// generated.
    pub fn timestamp_delayed(&self) -> bool {
        self.tc & 0b01 == 0b01
    }

    /// Output of the ITM or DWT packet corresponding to this Local timestamp packet is delayed
    /// relative to the associated event.
    ///
    /// The value in the TS field is the timestamp counter value when the ITM or DWT packets is
    /// generated.
    ///
    /// This encoding indicates that the ITM or DWT packet was delayed relative to other trace
    /// output packets.
    pub fn event_delayed(&self) -> bool {
        self.tc & 0b10 == 0b10
    }
}

/// Extension packet for the stimulus port page number
#[derive(Debug)]
pub struct ExtensionStimulusPortPage {
    pub(crate) page: u8,
}

impl ExtensionStimulusPortPage {
    /// Stimulus port page number
    pub fn page(&self) -> u8 {
        self.page
    }
}

/// Event counter packet
#[derive(Debug)]
pub struct EventCounter {
    pub(crate) payload: u8,
}

impl EventCounter {
    /// has CPICNT wrapped around?
    pub fn cpi(&self) -> bool {
        self.payload & (1 << 0) != 0
    }

    /// has EXCCNT wrapped around?
    pub fn exc(&self) -> bool {
        self.payload & (1 << 1) != 0
    }

    /// has SLEEPCNT wrapped around?
    pub fn sleep(&self) -> bool {
        self.payload & (1 << 2) != 0
    }

    /// has LSUCNT wrapped around?
    pub fn lsu(&self) -> bool {
        self.payload & (1 << 3) != 0
    }

    /// has FOLDCNT wrapped around?
    pub fn fold(&self) -> bool {
        self.payload & (1 << 4) != 0
    }

    /// has POSTCNT wrapped around?
    pub fn post(&self) -> bool {
        self.payload & (1 << 5) != 0
    }
}

/// Periodic PC sample packet
#[derive(Clone, Copy, Debug)]
pub struct PeriodicPcSample {
    pub(crate) pc: Option<u32>,
}

impl PeriodicPcSample {
    /// Returns sampled PC
    ///
    /// `None` means that the core is sleeping (`wfi` / `wfe`)
    pub fn pc(&self) -> Option<u32> {
        self.pc
    }
}

/// Data trace PC packet
#[derive(Debug)]
pub struct DataTracePcValue {
    pub(crate) cmpn: u8,
    pub(crate) pc: u32,
}

impl DataTracePcValue {
    /// Comparator that generated the data
    pub fn comparator(&self) -> u8 {
        self.cmpn
    }

    /// PC value for the instruction that caused the successful address comparison
    pub fn pc(&self) -> u32 {
        self.pc
    }
}

/// Data trace address packet
#[derive(Debug)]
pub struct DataTraceAddress {
    pub(crate) cmpn: u8,
    pub(crate) addr: u16,
}

impl DataTraceAddress {
    /// Data address that caused the successful address comparison
    pub fn address(&self) -> u16 {
        self.addr
    }

    /// Comparator that generated the data
    pub fn comparator(&self) -> u8 {
        self.cmpn
    }
}

/// Data trace data value packet
#[derive(Debug)]
pub struct DataTraceDataValue {
    pub(crate) cmpn: u8,
    pub(crate) len: usize,
    pub(crate) payload: [u8; MAX_PAYLOAD_SIZE],
    pub(crate) wnr: bool,
}

impl DataTraceDataValue {
    /// Comparator that generated the data
    pub fn comparator(&self) -> u8 {
        self.cmpn
    }

    /// Was this a read access?
    pub fn read_access(&self) -> bool {
        !self.wnr
    }

    /// Data value that caused the successful data value comparison
    pub fn value(&self) -> &[u8] {
        &self.payload[..self.len]
    }

    /// Was this a write access?
    pub fn write_access(&self) -> bool {
        self.wnr
    }
}
