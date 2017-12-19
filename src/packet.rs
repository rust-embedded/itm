//! Defines ITM packets and their possible contents.

use heapless::Vec as HVec;

pub const MAX_PAYLOAD_SIZE: usize = 4;

/// Represents a complete received packet.
pub struct Packet {
    /// The header byte received for this packet.
    pub header: u8,

    /// The kind (type) of this packet.
    pub kind: Kind,
}

/// The type of a packet.
pub enum Kind {
    /// Data from a software application
    Instrumentation(Instrumentation),

    #[doc(hidden)]
    /// External consumers shouldn't expect the public variants to
    /// be complete: there are more variants to implement.
    _NoExhaustiveMatch,
}

/// Contents of an Instrumentation packet, with data from a software application
pub struct Instrumentation {
    /// Data in this packet.
    pub payload: HVec<u8, [u8; MAX_PAYLOAD_SIZE]>,

    /// Stimulus port this packet was sent from.
    pub port: u8,
}
