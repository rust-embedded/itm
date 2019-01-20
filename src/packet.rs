//! ITM packets

use core::fmt;

/// Synchronization packet
#[derive(Clone, Copy, Debug)]
pub struct Synchronization {
    pub(crate) len: u8,
}

impl Synchronization {
    /// The length in bytes of this synchronization packet
    pub fn len(&self) -> u8 {
        self.len
    }
}

/// Instrumentation packet
#[derive(Clone, Copy)]
pub struct Instrumentation {
    pub(crate) buffer: [u8; 4],
    pub(crate) port: u8,
    pub(crate) size: u8,
}

impl Instrumentation {
    /// The stimulus port that generated this packet
    pub fn port(&self) -> u8 {
        self.port
    }

    /// The payload of this packet
    pub fn payload(&self) -> &[u8] {
        &self.buffer[..usize::from(self.size)]
    }
}

impl fmt::Debug for Instrumentation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Instrumentation")
            .field("payload", &&self.buffer[..usize::from(self.size)])
            .field("port", &self.port)
            .finish()
    }
}

/// Local timestamp packet
#[derive(Clone, Copy, Debug)]
pub struct LocalTimestamp {
    pub(crate) delta: u32,
    // TC[1:0] bits
    pub(crate) tc: u8,
    // Size of this packet in bytes, including the header
    pub(crate) len: u8,
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

/// Global timestamp packet (format 1)
#[derive(Clone, Copy, Debug)]
pub struct GTS1 {
    pub(crate) bits: u32,
    pub(crate) clk_ch: bool,
    // Size of this packet in bytes, including the header
    pub(crate) len: u8,
    pub(crate) wrap: bool,
}

impl GTS1 {
    /// Timestamp bits (up to 26 bits)
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// The system has asserted the clock change input to the processor since the last time the ITM
    /// generated a Global timestamp packet
    ///
    /// When this signal is asserted, the ITM must output a full 48-bit or 64-bit global timestamp
    /// value.
    pub fn has_clock_changed(&self) -> bool {
        self.clk_ch
    }

    /// The value of global timestamp bits TS[47:26] or TS[63:26] have changed since the last GTS2
    /// packet output by the ITM
    pub fn has_wrapped(&self) -> bool {
        self.wrap
    }
}

/// Global timestamp packet (format 2)
#[derive(Clone, Copy, Debug)]
pub struct GTS2 {
    pub(crate) bits: u64,
    pub(crate) b64: bool,
}

impl GTS2 {
    /// High-order bits of the global timestamp
    pub fn bits(&self) -> u64 {
        self.bits
    }

    /// This is a 64-bit timestamp
    pub fn is_64_bit(&self) -> bool {
        self.b64
    }
}

/// Stimulus Port Page (Extension packet)
#[derive(Clone, Copy, Debug)]
pub struct StimulusPortPage {
    pub(crate) page: u8,
}

impl StimulusPortPage {
    /// Stimulus port page (3-bit value)
    pub fn page(&self) -> u8 {
        self.page
    }
}

/// Event counter packet
#[derive(Clone, Copy, Debug)]
pub struct EventCounter {
    pub(crate) payload: u8,
}

impl EventCounter {
    /// has CPICNT wrapped around?
    pub fn cpi(&self) -> bool {
        self.payload & 1 != 0
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

/// Exception trace packet
#[derive(Clone, Copy, Debug)]
pub struct ExceptionTrace {
    pub(crate) function: Function,
    pub(crate) number: u16,
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
#[derive(Clone, Copy, Debug)]
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
#[derive(Clone, Copy, Debug)]
pub struct DataTraceAddress {
    pub(crate) cmpn: u8,
    pub(crate) address: u16,
}

impl DataTraceAddress {
    /// Data address that caused the successful address comparison
    pub fn address(&self) -> u16 {
        self.address
    }

    /// Comparator that generated the data
    pub fn comparator(&self) -> u8 {
        self.cmpn
    }
}

/// Data trace data value packet
#[derive(Clone, Copy)]
pub struct DataTraceDataValue {
    pub(crate) buffer: [u8; 4],
    pub(crate) cmpn: u8,
    pub(crate) size: u8,
    pub(crate) wnr: bool,
}

impl fmt::Debug for DataTraceDataValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("DataTraceDataValue")
            .field("cmpn", &self.cmpn)
            .field("value", &self.value())
            .field("wnr", &self.wnr)
            .finish()
    }
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
        &self.buffer[..usize::from(self.size)]
    }

    /// Was this a write access?
    pub fn write_access(&self) -> bool {
        self.wnr
    }
}
