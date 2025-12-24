//! Signaling layer for tunnel connection establishment.
//!
//! This module provides signaling mechanisms for exchanging connection information:
//! - `codec`: Payload types and encoding/decoding for ICE offers/answers
//! - `manual`: Stdin/stdout helpers for manual copy-paste signaling
//! - `nostr`: Nostr relay-based automated signaling
//! - `dcutr`: DCUtR-style signaling with timing coordination

pub mod codec;
pub mod dcutr;
pub mod manual;
pub mod nostr;

// Re-export commonly used types
pub use codec::{
    decode_answer, decode_offer, decode_source_request, decode_source_response, encode_answer,
    encode_offer, encode_source_request, encode_source_response, read_length_prefixed,
    IrohManualAnswer, IrohManualOffer, ManualAnswer, ManualOffer, ManualReject, ManualRequest,
    SourceRequest, SourceResponse, IROH_SIGNAL_VERSION, MANUAL_SIGNAL_VERSION,
};
pub use manual::{
    display_answer, display_iroh_answer, display_iroh_offer, display_offer,
    read_answer_from_stdin, read_iroh_answer_from_stdin, read_iroh_offer_from_stdin,
    read_offer_from_stdin,
};
pub use nostr::{NostrSignaling, OfferWaitError, SignalingError};
