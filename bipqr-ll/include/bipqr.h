/* C binding for the QR signing codec, signer direction.
 *
 * Kept in sync by hand with src/ffi/types.rs. The wire format is
 * specified in ENCODING.md.
 *
 * Ownership: this library never frees memory you own, and you never free memory it
 * owns except through bipqr_request_free and bipqr_buf_free. On encode your struct
 * is borrowed for the duration of the call only.
 */

#ifndef BIPQR_H
#define BIPQR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIPQR_REQUEST_ID_LEN 2
#define BIPQR_MAX_DESCRIPTOR_ALIAS 32
#define BIPQR_EXTENDED_KEY_LEN 78
#define BIPQR_FINGERPRINT_LEN 4
#define BIPQR_PUBLIC_KEY_LEN 33
#define BIPQR_SECRET_KEY_LEN 32
#define BIPQR_MUSIG_PUB_NONCE_LEN 66
#define BIPQR_MUSIG_PARTIAL_SIG_LEN 32
#define BIPQR_TAP_LEAF_HASH_LEN 32
#define BIPQR_DLEQ_PROOF_LEN 64
#define BIPQR_SCHNORR_SIGNATURE_LEN 64 /* 65 with a sighash type byte */

/* Sizes and limits stay macros: they are array dimensions and a consumer may want
 * them in an #if. Everything a field can hold is an enum below.
 *
 * No field or return type is declared as one of these enum types. A C enum's size is
 * implementation-defined while the wire fields are one byte, so the structs use
 * uint8_t and the functions return int32_t. The enums name the values, they do not
 * type them. */

/* Closed: the decoder rejects any other value. */
enum bipqr_message_type {
    BIPQR_MESSAGE_GET_INFO = 0x01, /* no request body: the body union is unused */
    BIPQR_MESSAGE_GET_KEYS = 0x02,
    BIPQR_MESSAGE_REGISTER_DESCRIPTOR = 0x03,
    BIPQR_MESSAGE_ADDRESS_VERIFICATION = 0x04,
    BIPQR_MESSAGE_SIGNING = 0x05,
    BIPQR_MESSAGE_NONCE_PREPARATION = 0x06
};

enum bipqr_capability {
    BIPQR_CAPABILITY_NONCE_CACHE = 1u << 4,
    BIPQR_CAPABILITY_PSBT_TRIMMING = 1u << 5
};

/* Open: a value outside this list is a newer state, which counts as not ready. To
 * encode, it must sit above BIPQR_STATE_UNINITIALIZED. */
enum bipqr_state {
    BIPQR_STATE_READY = 0x00,
    BIPQR_STATE_LOCKED = 0x01,
    BIPQR_STATE_UNINITIALIZED = 0x02
};

/* Encoding a response rejects any other bit. */
enum bipqr_network {
    BIPQR_NETWORK_MAINNET = 1u << 1,
    BIPQR_NETWORK_TESTNET = 1u << 2,
    BIPQR_NETWORK_SIGNET = 1u << 3,
    BIPQR_NETWORK_REGTEST = 1u << 4
};

/* Closed: the decoder rejects any other value. */
enum bipqr_key_kind {
    BIPQR_KEY_PUBLIC = 0x00,
    BIPQR_KEY_PRIVATE = 0x01
};

/* Closed: the decoder rejects any other value. */
enum bipqr_descriptor_form {
    BIPQR_DESCRIPTOR_BIP380 = 0x01,
    BIPQR_DESCRIPTOR_BIP388 = 0x02,
    BIPQR_DESCRIPTOR_SP_KEYS = 0x03
};

/* Closed: the decoder rejects any other value. */
enum bipqr_sign_response_kind {
    BIPQR_SIGN_RESPONSE_PSBT = 0x01,
    BIPQR_SIGN_RESPONSE_SIGNATURES = 0x02
};

/* Closed: encoding a response rejects any other value. */
enum bipqr_signature_kind {
    BIPQR_SIGNATURE_ECDSA = 0x01,
    BIPQR_SIGNATURE_TAP_KEY = 0x02,
    BIPQR_SIGNATURE_TAP_SCRIPT = 0x03,
    BIPQR_SIGNATURE_MUSIG_PUB_NONCE = 0x04,
    BIPQR_SIGNATURE_MUSIG_PARTIAL_SIG = 0x05,
    BIPQR_SIGNATURE_SP_ECDH_SHARE = 0x06,
    BIPQR_SIGNATURE_SP_DLEQ_PROOF = 0x07
};

/* Open: a value outside this list is a newer flag and passes through unchanged. */
enum bipqr_release_flag {
    BIPQR_RELEASE_STABLE = 0x00,
    BIPQR_RELEASE_ALPHA = 0x01,
    BIPQR_RELEASE_BETA = 0x02,
    BIPQR_RELEASE_CANDIDATE = 0x03
};

/* Open: a value outside this list passes through as an unknown code, and must sit in
 * 0x11..=0xfe to encode. */
enum bipqr_response_error {
    BIPQR_RESPONSE_ERROR_USER_DECLINED = 0x01,
    BIPQR_RESPONSE_ERROR_UNSUPPORTED_VERSION = 0x02,
    BIPQR_RESPONSE_ERROR_MALFORMED_REQUEST = 0x03,
    BIPQR_RESPONSE_ERROR_UNKNOWN_DESCRIPTOR_ALIAS = 0x04,
    BIPQR_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED = 0x05,
    BIPQR_RESPONSE_ERROR_UNSUPPORTED_DESCRIPTOR_FORM = 0x06,
    BIPQR_RESPONSE_ERROR_INVALID_PROOF = 0x07,
    BIPQR_RESPONSE_ERROR_ADDRESS_MISMATCH = 0x08,
    BIPQR_RESPONSE_ERROR_NOTHING_TO_SIGN = 0x09,
    BIPQR_RESPONSE_ERROR_INVALID_PSBT = 0x0a,
    BIPQR_RESPONSE_ERROR_INTERNAL = 0x0b,
    BIPQR_RESPONSE_ERROR_PRIVATE_KEY_EXPORT_REFUSED = 0x0c,
    BIPQR_RESPONSE_ERROR_MUSIG_SESSION = 0x0d,
    BIPQR_RESPONSE_ERROR_ALREADY_REGISTERED = 0x0e,
    BIPQR_RESPONSE_ERROR_UNSUPPORTED_OPERATION = 0x0f,
    BIPQR_RESPONSE_ERROR_NETWORK_MISMATCH = 0x10,
    BIPQR_RESPONSE_ERROR_VENDOR = 0xff
};

/* Selects the scan arm of bipqr_sp_keys. Not a wire value: the wire carries the
 * scan path and the scan key as two optional fields, exactly one present. */
enum bipqr_scan_kind {
    BIPQR_SCAN_PATH = 0x00, /* the signer's own scan key, at scan.path */
    BIPQR_SCAN_KEY = 0x01   /* a scan private key the signer does not hold */
};

enum bipqr_absent {
    BIPQR_ABSENT_BOOL = -1,
    BIPQR_ABSENT_KIND = -1
};

/* What the four functions return. 100..=199 come from the byte reader, 200..=299
 * from the decoder, 300..=399 from the encoder, 400..=499 from this binding and
 * 500..=599 from a protocol rule the message breaks, both on encode and decode. */
enum bipqr_status {
    BIPQR_OK = 0,

    BIPQR_ERR_TRUNCATED = 100,
    BIPQR_ERR_LENGTH_OVERFLOW = 101,
    BIPQR_ERR_NON_CANONICAL_COMPACT_SIZE = 102,
    BIPQR_ERR_COMPACT_SIZE_TOO_LARGE = 103,
    BIPQR_ERR_INVALID_BOOL = 104,
    BIPQR_ERR_INVALID_PRESENCE = 105,
    BIPQR_ERR_STRING_TOO_LARGE = 106,
    BIPQR_ERR_INVALID_UTF8 = 110,
    BIPQR_ERR_STRING_NUL = 111,

    BIPQR_ERR_INVALID_MAGIC = 200,
    BIPQR_ERR_RESERVED_VERSION = 201,
    BIPQR_ERR_UNKNOWN_MESSAGE_TYPE = 202,
    BIPQR_ERR_ERROR_STATUS_ON_REQUEST = 203,
    BIPQR_ERR_UNKNOWN_DESCRIPTOR_FORM = 204,
    BIPQR_ERR_UNKNOWN_SIGN_RESPONSE_KIND = 206,
    BIPQR_ERR_UNKNOWN_KEY_KIND = 207,
    BIPQR_ERR_SIGNATURE_LENGTH = 208,
    BIPQR_ERR_GLOBAL_INPUT_INDEX = 209,
    BIPQR_ERR_SCAN_PATH_AND_KEY = 210,
    BIPQR_ERR_NO_SCAN = 211,
    BIPQR_ERR_UNPAIRED_SESSION = 212,

    BIPQR_ERR_PATH_TOO_LONG = 300,
    BIPQR_ERR_PATCH_TOO_LARGE = 301,
    BIPQR_ERR_RESERVED_CAPABILITY_BITS = 302,
    BIPQR_ERR_ERROR_CODE_OUT_OF_RANGE = 303,
    BIPQR_ERR_STRING_TOO_LONG = 306,
    BIPQR_ERR_ENCODE_STRING_NUL = 307,
    BIPQR_ERR_UNREACHABLE = 309,
    BIPQR_ERR_DEFINED_SIGNATURE_KIND = 310,
    BIPQR_ERR_RESERVED_NETWORK_BITS = 311,
    BIPQR_ERR_DEFINED_STATE = 312,
    BIPQR_ERR_DEFINED_RELEASE_FLAG = 313,

    BIPQR_ERR_NULL_POINTER = 400,
    BIPQR_ERR_FFI_STRING_NUL = 401,
    BIPQR_ERR_FFI_INVALID_UTF8 = 402,
    BIPQR_ERR_FFI_INVALID_BOOL = 403,
    BIPQR_ERR_UNKNOWN_TAG = 404,
    BIPQR_ERR_UNEXPECTED_RESPONSE = 406,
    BIPQR_ERR_FFI_GLOBAL_INPUT_INDEX = 407,

    BIPQR_ERR_DUPLICATE_SP_SHARE = 500,
    BIPQR_ERR_DUPLICATE_SP_PROOF = 501,
    BIPQR_ERR_MISSING_SP_PROOF = 502,
    BIPQR_ERR_MISSING_SP_SHARE = 503,
    BIPQR_ERR_MAX_ALIAS_TOO_LARGE = 504,
    BIPQR_ERR_FINGERPRINT_WHEN_NOT_READY = 505,
    BIPQR_ERR_TAPROOT_SIGNATURE_LENGTH = 506,
    BIPQR_ERR_ZERO_MAX_INPUTS = 507,
    BIPQR_ERR_REVERSED_EXPRESSION_RANGE = 508,
    BIPQR_ERR_SESSION_REF_WITHOUT_ID = 509
};

/* A borrowed run of items. A NULL ptr means the field is absent, which is distinct
 * from a present but empty run (non-NULL ptr with len 0). */
typedef struct {
    const uint8_t *ptr;
    size_t len;
} bipqr_bytes;

/* BIP-32 child numbers with the hardened bit set. */
typedef struct {
    const uint32_t *ptr;
    uint8_t len;
} bipqr_path;

typedef struct {
    bipqr_path derivation_path;
    uint8_t kind; /* BIPQR_KEY_* */
} bipqr_key_request;

typedef struct {
    const bipqr_key_request *ptr;
    size_t len;
} bipqr_key_request_list;

typedef struct {
    const char *const *ptr;
    size_t len;
} bipqr_string_list;

/* BIP-32 serialization of an extended public or private key. */
typedef struct {
    uint8_t bytes[BIPQR_EXTENDED_KEY_LEN];
} bipqr_extended_key;

typedef struct {
    const bipqr_extended_key *ptr;
    size_t len;
} bipqr_extended_key_list;

/* Strings are UTF-8 and NUL-terminated. The codec rejects an interior NUL on both
 * sides, so a string never carries one. A NULL pointer means the field is absent. */

typedef struct {
    bipqr_string_list keys;
    const char *policy;
} bipqr_bip388;

typedef union {
    bipqr_path path;                     /* from the master key */
    uint8_t key[BIPQR_SECRET_KEY_LEN];   /* big-endian scalar */
} bipqr_scan_value;

typedef struct {
    uint8_t fingerprint[BIPQR_FINGERPRINT_LEN];
    bipqr_path spend_path; /* from the master key */
    uint8_t scan_kind;      /* BIPQR_SCAN_*, selects the scan arm */
    bipqr_scan_value scan;
} bipqr_sp_keys;

typedef union {
    const char *bip380;
    bipqr_bip388 bip388;
    bipqr_sp_keys sp_keys;
} bipqr_descriptor_value;

typedef struct {
    uint8_t tag; /* BIPQR_DESCRIPTOR_* */
    bipqr_descriptor_value value;
} bipqr_descriptor_body;

typedef struct {
    const char *alias;
    const bipqr_descriptor_body *body;
    bipqr_bytes proof;
} bipqr_descriptor;

typedef struct {
    const bipqr_descriptor *ptr;
    size_t len;
} bipqr_descriptor_list;

typedef struct {
    bipqr_key_request_list keys;
} bipqr_get_keys;

typedef struct {
    const char *descriptor_alias;
    const bipqr_descriptor_body *descriptor; /* NULL when absent */
} bipqr_register_descriptor;

typedef struct {
    const char *descriptor_alias;
    bipqr_path derivation_path;
    const char *address;                      /* NULL when absent */
    const bipqr_descriptor_body *descriptor; /* NULL when absent */
    bipqr_bytes proof;                       /* ptr NULL when absent */
} bipqr_verify_address;

typedef struct {
    bipqr_descriptor_list descriptors;
    bipqr_bytes psbt; /* BIP-174 serialization, carried unparsed */
    int16_t want_kind; /* BIPQR_SIGN_RESPONSE_* or BIPQR_ABSENT_KIND */
    bool accept_trimmed; /* a PSBT answer may leave out fields of psbt */
} bipqr_sign;

/* start..=end: key expression indexes, start <= end; start alone without end. */
typedef struct {
    uint8_t has_session_id; /* 0 or 1, the signer draws one when 0 */
    uint8_t session_id[4];
    uint8_t has_session_ref; /* 0 or 1 */
    uint8_t session_ref[4];
    const bipqr_descriptor *descriptor; /* NULL when absent */
    uint32_t max_inputs;
    bipqr_path derivation_path; /* from the master key */
    uint32_t start;
    uint8_t has_end; /* 0 or 1 */
    uint32_t end;
} bipqr_prepare_nonces;

typedef union {
    bipqr_get_keys get_keys;
    bipqr_register_descriptor register_descriptor;
    bipqr_verify_address verify_address;
    bipqr_sign sign;
    bipqr_prepare_nonces prepare_nonces;
} bipqr_request_body;

typedef struct {
    uint8_t id[BIPQR_REQUEST_ID_LEN];
    uint8_t message_type; /* BIPQR_MESSAGE_*, selects the body arm */
    bipqr_request_body body;
} bipqr_request;

typedef struct {
    uint16_t major;
    uint16_t minor;
    uint32_t patch; /* at most 0x00ffffff */
    uint8_t flag;   /* BIPQR_RELEASE_* */
} bipqr_firmware_version;

typedef struct {
    bipqr_extended_key_list keys; /* one per request key, in request order */
    uint8_t fingerprint[BIPQR_FINGERPRINT_LEN];
    const char *vendor;
    const char *model;
    bipqr_firmware_version version;
    uint32_t capabilities; /* only the low six bits may be set */
} bipqr_keys;

typedef struct {
    const char *vendor;
    const char *model;
    bipqr_firmware_version version;
    uint32_t capabilities;   /* only the low six bits may be set */
    uint8_t state;           /* BIPQR_STATE_* */
    uint8_t networks;        /* BIPQR_NETWORK_* bits */
    uint32_t max_message;    /* bytes */
    uint8_t max_alias;       /* at most BIPQR_MAX_DESCRIPTOR_ALIAS */
    uint8_t has_fingerprint; /* 0 or 1, and 1 only when state is BIPQR_STATE_READY */
    uint8_t fingerprint[BIPQR_FINGERPRINT_LEN];
} bipqr_info;

typedef struct {
    const char *descriptor_alias;
    bool registered;
    int8_t stored;       /* 0, 1 or BIPQR_ABSENT_BOOL */
    bipqr_bytes proof;
} bipqr_registration;

typedef struct {
    const char *uri; /* BIP-321 payment URI for the verified address */
} bipqr_address_uri;

typedef struct {
    uint8_t public_key[BIPQR_PUBLIC_KEY_LEN]; /* compressed */
    bipqr_bytes signature;
} bipqr_ecdsa;

typedef struct {
    bipqr_bytes signature;
} bipqr_tap_key;

typedef struct {
    uint8_t xonly_public_key[32];
    uint8_t tap_leaf_hash[32];
    bipqr_bytes signature;
} bipqr_tap_script;

typedef struct {
    uint8_t participant[BIPQR_PUBLIC_KEY_LEN];
    uint8_t aggregate[BIPQR_PUBLIC_KEY_LEN];
    uint8_t has_leaf_hash; /* 0 or 1 */
    uint8_t leaf_hash[BIPQR_TAP_LEAF_HASH_LEN];
    uint8_t nonce[BIPQR_MUSIG_PUB_NONCE_LEN];
} bipqr_musig_pub_nonce;

typedef struct {
    uint8_t participant[BIPQR_PUBLIC_KEY_LEN];
    uint8_t aggregate[BIPQR_PUBLIC_KEY_LEN];
    uint8_t has_leaf_hash; /* 0 or 1 */
    uint8_t leaf_hash[BIPQR_TAP_LEAF_HASH_LEN];
    uint8_t signature[BIPQR_MUSIG_PARTIAL_SIG_LEN];
} bipqr_musig_partial_sig;

typedef struct {
    uint8_t global; /* 0 for the input at input_index, 1 for the whole transaction */
    uint8_t scan_key[BIPQR_PUBLIC_KEY_LEN];
    uint8_t share[BIPQR_PUBLIC_KEY_LEN];
} bipqr_sp_ecdh_share;

typedef struct {
    uint8_t global; /* 0 for the input at input_index, 1 for the whole transaction */
    uint8_t scan_key[BIPQR_PUBLIC_KEY_LEN];
    uint8_t proof[BIPQR_DLEQ_PROOF_LEN]; /* BIP-374 */
} bipqr_sp_dleq_proof;

typedef struct {
    uint8_t bytes[BIPQR_MUSIG_PUB_NONCE_LEN];
} bipqr_pub_nonce;

typedef struct {
    const bipqr_pub_nonce *ptr;
    size_t len;
} bipqr_pub_nonce_list;

/* nonces: (end - start + 1) * max_inputs entries of the request, the one for key
 * expression index j and input i at (j - start) * max_inputs + i. */
typedef struct {
    uint8_t has_session; /* 0 or 1, 1 only for a new session */
    uint8_t session_id[4];
    uint8_t session_ref[4];
    bipqr_pub_nonce_list nonces;
} bipqr_nonces_prepared;

typedef union {
    bipqr_ecdsa ecdsa;
    bipqr_tap_key tap_key;
    bipqr_tap_script tap_script;
    bipqr_musig_pub_nonce musig_pub_nonce;
    bipqr_musig_partial_sig musig_partial_sig;
    bipqr_sp_ecdh_share sp_ecdh_share;
    bipqr_sp_dleq_proof sp_dleq_proof;
} bipqr_signature_value;

typedef struct {
    uint32_t input_index; /* 0 for a global silent payment entry */
    uint8_t kind; /* BIPQR_SIGNATURE_*, selects the value arm */
    bipqr_signature_value value;
} bipqr_signature;

typedef struct {
    const bipqr_signature *ptr;
    size_t len;
} bipqr_signature_list;

typedef union {
    bipqr_bytes psbt;
    bipqr_signature_list signatures;
} bipqr_signed_value;

typedef struct {
    uint8_t kind; /* BIPQR_SIGN_RESPONSE_*, selects the value arm */
    bipqr_signed_value value;
} bipqr_signed;

typedef struct {
    uint8_t error; /* BIPQR_RESPONSE_ERROR_* */
    const char *message;
} bipqr_error_body;

typedef union {
    bipqr_keys keys;
    bipqr_registration registration;
    bipqr_address_uri address_uri;
    bipqr_signed signed_body;
    bipqr_nonces_prepared nonces_prepared;
    bipqr_info info;
    bipqr_error_body error;
} bipqr_response_body;

typedef struct {
    uint8_t id[BIPQR_REQUEST_ID_LEN];
    uint8_t message_type; /* BIPQR_MESSAGE_*, selects the body arm */
    bool is_error;        /* when true the body is the error arm */
    bipqr_response_body body;
} bipqr_response;

/* A byte buffer the codec allocated. Release it with bipqr_buf_free. */
typedef struct {
    uint8_t *ptr;
    size_t len;
} bipqr_buf;

/* Decodes a request. On BIPQR_OK, *out owns the tree until bipqr_request_free.
 * err may be NULL; otherwise a failure writes a static message to it. */
int32_t bipqr_request_decode(const uint8_t *bytes, size_t len,
                              const bipqr_request **out, const char **err);

/* Releases a request from bipqr_request_decode. NULL is a no-op. */
void bipqr_request_free(const bipqr_request *request);

/* Encodes a response. On BIPQR_OK, *out owns the bytes until bipqr_buf_free. */
int32_t bipqr_response_encode(const bipqr_response *response, bipqr_buf *out,
                               const char **err);

/* Releases a buffer from the codec. A NULL ptr is a no-op. */
void bipqr_buf_free(bipqr_buf buf);

#ifdef __cplusplus
}
#endif

#endif /* BIPQR_H */
