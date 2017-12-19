//! Defines ITM packets and their possible contents.

use heapless::Vec as HVec;

pub const MAX_PAYLOAD_SIZE: usize = 4;

pub struct Packet {
    /// The header byte received for this packet.
    pub header: u8,

    /// The kind (type) of this packet.
    pub kind: Kind,
}

pub enum Kind {
    UserData(UserData),

    #[doc(hidden)]
    /// External consumers shouldn't expect the public variants to
    /// be complete: there are more variants to implement.
    _NoExhaustiveMatch,
}

pub struct UserData {
    /// Data in this packet.
    pub payload: HVec<u8, [u8; MAX_PAYLOAD_SIZE]>,

    /// Stimulus port this packet was sent from.
    pub port: u8,
}
