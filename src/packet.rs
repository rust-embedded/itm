//! Defines ITM packets and their possible contents.

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
