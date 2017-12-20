//! Defines ITM packets and their possible contents.

use heapless::Vec as HVec;
use std::fmt::{self, Debug, Formatter};

pub const MAX_PAYLOAD_SIZE: usize = 4;

/// Represents a complete received packet.
#[derive(Debug)]
pub struct Packet {
    /// The header byte received for this packet.
    pub header: u8,

    /// The kind (type) of this packet.
    pub kind: Kind,
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
pub struct Instrumentation {
    /// Data in this packet.
    pub payload: HVec<u8, [u8; MAX_PAYLOAD_SIZE]>,

    /// Stimulus port this packet was sent from.
    pub port: u8,
}

impl Debug for Instrumentation {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        // TODO: impl Debug for heapless::Vec, then this can just be derived.
        //       Eq, PartialEq, Clone would be good too.

        f.debug_struct("Instrumentation")
         .field("payload", &&*self.payload)
         .field("port", &self.port)
         .finish()
    }
}
