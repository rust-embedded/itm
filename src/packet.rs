//! Defines ITM packets and their possible contents.

use heapless::Vec as HVec;

pub const MAX_PAYLOAD_SIZE: usize = 4;

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
    /// Data from a software application
    Instrumentation(Instrumentation),

    #[doc(hidden)]
    /// External consumers shouldn't expect the public variants to
    /// be complete: there are more variants to implement.
    _NoExhaustiveMatch,
}

/// Contents of an Instrumentation packet, with data from a software application
#[derive(Debug)]
pub struct Instrumentation {
    /// Data in this packet.
    pub(crate) payload: HVec<u8, [u8; MAX_PAYLOAD_SIZE]>,

    /// Stimulus port this packet was sent from.
    pub(crate) port: u8,
}

impl Instrumentation {
    /// Data in this packet.
    pub fn payload(&self) -> &[u8] {
        &*self.payload
    }

    /// Stimulus port this packet was sent from.
    pub fn port(&self) -> u8 {
        self.port
    }
}
