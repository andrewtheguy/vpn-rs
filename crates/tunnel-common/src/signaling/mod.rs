//! Common signaling codecs shared by iroh and ice modes.

pub mod codec;

pub use codec::{
    decode_source_request, decode_source_response, encode_source_request, encode_source_response,
    read_length_prefixed, SourceRequest, SourceResponse,
};

pub use codec::{
    decode_answer, decode_offer, encode_answer, encode_offer, ManualAnswer, ManualOffer,
    ManualReject, ManualRequest, MANUAL_SIGNAL_VERSION,
};
