//! Signaling layer for tunnel connection establishment.
//!
//! This module provides signaling mechanisms for exchanging connection information:
//! - `codec`: Payload types and encoding/decoding for ICE offers/answers
//! - `manual`: Stdin/stdout helpers for manual copy-paste signaling
//! - `nostr`: Nostr relay-based automated signaling (requires ice feature)

pub mod codec;
#[cfg(feature = "ice")]
pub mod manual;
#[cfg(feature = "ice")]
pub mod nostr;

// Re-export commonly used types
pub use codec::{
    decode_source_request, decode_source_response,
    encode_source_request, encode_source_response, read_length_prefixed,
    SourceRequest, SourceResponse,
};

// ICE-only re-exports
#[cfg(feature = "ice")]
pub use codec::{
    decode_answer, decode_offer, encode_answer, encode_offer,
    ManualAnswer, ManualOffer, ManualReject, ManualRequest, MANUAL_SIGNAL_VERSION,
};
#[cfg(feature = "ice")]
pub use manual::{
    display_answer, display_offer,
    read_answer_from_stdin, read_offer_from_stdin,
};
#[cfg(feature = "ice")]
pub use nostr::{NostrSignaling, OfferWaitError, SignalingError};
