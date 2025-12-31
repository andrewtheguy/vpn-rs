//! Common signaling codecs shared by iroh and ice modes.

pub mod codec;

pub use codec::{
    decode_auth_request, decode_auth_response, decode_source_request, decode_source_response,
    encode_auth_request, encode_auth_response, encode_source_request, encode_source_response,
    read_length_prefixed, AuthRequest, AuthResponse, AuthToken, SourceRequest, SourceResponse,
};

pub use codec::{
    decode_answer, decode_offer, encode_answer, encode_offer, ManualAnswer, ManualOffer,
    ManualReject, ManualRequest, MANUAL_SIGNAL_VERSION,
};
