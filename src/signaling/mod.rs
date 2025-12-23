//! Signaling layer for tunnel connection establishment.
//!
//! This module provides signaling mechanisms for exchanging connection information:
//! - `codec`: Payload types and encoding/decoding for ICE offers/answers
//! - `manual`: Stdin/stdout helpers for manual copy-paste signaling
//! - `nostr`: Nostr relay-based automated signaling

pub mod codec;
pub mod manual;
pub mod nostr;

// Re-export commonly used types
pub use codec::{
    decode_answer, decode_offer, encode_answer, encode_offer, IrohManualAnswer, IrohManualOffer,
    ManualAnswer, ManualOffer, ManualReject, ManualRequest, IROH_SIGNAL_VERSION,
    MANUAL_SIGNAL_VERSION,
};
pub use manual::{
    display_answer, display_iroh_answer, display_iroh_offer, display_offer,
    read_answer_from_stdin, read_iroh_answer_from_stdin, read_iroh_offer_from_stdin,
    read_offer_from_stdin,
};
pub use nostr::{NostrSignaling, OfferWaitError, SignalingError};
