/**
 * Narrow private libfido2 ABI used by the FIDO2 vault protector.
 *
 * This module intentionally declares only the CTAP/FIDO2 surface required for
 * device discovery, hmac-secret credential enrollment, and assertion-derived
 * wrapping keys.
 */
module credentials.backend.fido2.ffi;

package(credentials.backend.fido2):

struct FidoDev;
struct FidoCred;
struct FidoAssert;
struct FidoDevInfo;
struct FidoCborInfo;

alias fido_dev_t = FidoDev;
alias fido_cred_t = FidoCred;
alias fido_assert_t = FidoAssert;
alias fido_dev_info_t = FidoDevInfo;
alias fido_cbor_info_t = FidoCborInfo;

enum int FIDO_OK = 0;

enum int FIDO_DISABLE_U2F_FALLBACK = 0x02;

enum ubyte CTAP_AUTHDATA_USER_VERIFIED = 0x04;

enum int FIDO_EXT_HMAC_SECRET = 0x01;
enum int FIDO_EXT_CRED_PROTECT = 0x02;

enum int FIDO_CRED_PROT_UV_REQUIRED = 0x03;

enum int COSE_ES256 = -7;
enum int COSE_EDDSA = -8;
enum int COSE_ES384 = -35;
enum int COSE_RS256 = -257;

enum FidoOpt : int
{
    omit = 0,
    false_ = 1,
    true_ = 2
}

// CTAP/libfido2 errors used for stable non-secret status mapping.
enum int FIDO_ERR_INVALID_COMMAND = 0x01;
enum int FIDO_ERR_INVALID_PARAMETER = 0x02;
enum int FIDO_ERR_INVALID_LENGTH = 0x03;
enum int FIDO_ERR_INVALID_SEQ = 0x04;
enum int FIDO_ERR_TIMEOUT = 0x05;
enum int FIDO_ERR_CHANNEL_BUSY = 0x06;
enum int FIDO_ERR_LOCK_REQUIRED = 0x0a;
enum int FIDO_ERR_INVALID_CHANNEL = 0x0b;
enum int FIDO_ERR_CBOR_UNEXPECTED_TYPE = 0x11;
enum int FIDO_ERR_INVALID_CBOR = 0x12;
enum int FIDO_ERR_MISSING_PARAMETER = 0x14;
enum int FIDO_ERR_LIMIT_EXCEEDED = 0x15;
enum int FIDO_ERR_UNSUPPORTED_EXTENSION = 0x16;
enum int FIDO_ERR_FP_DATABASE_FULL = 0x17;
enum int FIDO_ERR_LARGEBLOB_STORAGE_FULL = 0x18;
enum int FIDO_ERR_CREDENTIAL_EXCLUDED = 0x19;
enum int FIDO_ERR_PROCESSING = 0x21;
enum int FIDO_ERR_INVALID_CREDENTIAL = 0x22;
enum int FIDO_ERR_USER_ACTION_PENDING = 0x23;
enum int FIDO_ERR_OPERATION_PENDING = 0x24;
enum int FIDO_ERR_NO_OPERATIONS = 0x25;
enum int FIDO_ERR_UNSUPPORTED_ALGORITHM = 0x26;
enum int FIDO_ERR_OPERATION_DENIED = 0x27;
enum int FIDO_ERR_KEY_STORE_FULL = 0x28;
enum int FIDO_ERR_NOT_BUSY = 0x29;
enum int FIDO_ERR_NO_OPERATION_PENDING = 0x2a;
enum int FIDO_ERR_UNSUPPORTED_OPTION = 0x2b;
enum int FIDO_ERR_INVALID_OPTION = 0x2c;
enum int FIDO_ERR_KEEPALIVE_CANCEL = 0x2d;
enum int FIDO_ERR_NO_CREDENTIALS = 0x2e;
enum int FIDO_ERR_USER_ACTION_TIMEOUT = 0x2f;
enum int FIDO_ERR_NOT_ALLOWED = 0x30;
enum int FIDO_ERR_PIN_INVALID = 0x31;
enum int FIDO_ERR_PIN_BLOCKED = 0x32;
enum int FIDO_ERR_PIN_AUTH_INVALID = 0x33;
enum int FIDO_ERR_PIN_AUTH_BLOCKED = 0x34;
enum int FIDO_ERR_PIN_NOT_SET = 0x35;
enum int FIDO_ERR_PIN_REQUIRED = 0x36;
enum int FIDO_ERR_PIN_POLICY_VIOLATION = 0x37;
enum int FIDO_ERR_PIN_TOKEN_EXPIRED = 0x38;
enum int FIDO_ERR_REQUEST_TOO_LARGE = 0x39;
enum int FIDO_ERR_ACTION_TIMEOUT = 0x3a;
enum int FIDO_ERR_UP_REQUIRED = 0x3b;
enum int FIDO_ERR_UV_BLOCKED = 0x3c;
enum int FIDO_ERR_UV_INVALID = 0x3f;
enum int FIDO_ERR_UNAUTHORIZED_PERM = 0x40;
enum int FIDO_ERR_ERR_OTHER = 0x7f;

enum int FIDO_ERR_TX = -1;
enum int FIDO_ERR_RX = -2;
enum int FIDO_ERR_RX_NOT_CBOR = -3;
enum int FIDO_ERR_RX_INVALID_CBOR = -4;
enum int FIDO_ERR_INVALID_PARAM = -5;
enum int FIDO_ERR_INVALID_SIG = -6;
enum int FIDO_ERR_INVALID_ARGUMENT = -7;
enum int FIDO_ERR_USER_PRESENCE_REQUIRED = -8;
enum int FIDO_ERR_INTERNAL = -9;
enum int FIDO_ERR_NOTFOUND = -10;
enum int FIDO_ERR_COMPRESS = -11;

extern(C) @nogc nothrow
{
    void fido_init(int flags);
    const(char)* fido_strerr(int status);

    fido_dev_info_t* fido_dev_info_new(size_t n);
    void fido_dev_info_free(fido_dev_info_t** list, size_t n);
    int fido_dev_info_manifest(
        fido_dev_info_t* list,
        size_t capacity,
        size_t* count
    );
    const(fido_dev_info_t)* fido_dev_info_ptr(
        const(fido_dev_info_t)* list,
        size_t index
    );
    const(char)* fido_dev_info_path(
        const(fido_dev_info_t)* info
    );
    const(char)* fido_dev_info_manufacturer_string(
        const(fido_dev_info_t)* info
    );
    const(char)* fido_dev_info_product_string(
        const(fido_dev_info_t)* info
    );

    fido_dev_t* fido_dev_new();
    void fido_dev_free(fido_dev_t** dev);
    int fido_dev_open(fido_dev_t* dev, const(char)* path);
    int fido_dev_close(fido_dev_t* dev);
    int fido_dev_cancel(fido_dev_t* dev);
    int fido_dev_set_timeout(fido_dev_t* dev, int milliseconds);

    fido_cbor_info_t* fido_cbor_info_new();
    void fido_cbor_info_free(fido_cbor_info_t** info);
    int fido_dev_get_cbor_info(
        fido_dev_t* dev,
        fido_cbor_info_t* info
    );
    const(char*)* fido_cbor_info_extensions_ptr(
        const(fido_cbor_info_t)* info
    );
    size_t fido_cbor_info_extensions_len(
        const(fido_cbor_info_t)* info
    );
    const(char*)* fido_cbor_info_options_name_ptr(
        const(fido_cbor_info_t)* info
    );
    const(bool)* fido_cbor_info_options_value_ptr(
        const(fido_cbor_info_t)* info
    );
    size_t fido_cbor_info_options_len(
        const(fido_cbor_info_t)* info
    );
    size_t fido_cbor_info_algorithm_count(
        const(fido_cbor_info_t)* info
    );
    int fido_cbor_info_algorithm_cose(
        const(fido_cbor_info_t)* info,
        size_t index
    );
    ulong fido_cbor_info_fwversion(
        const(fido_cbor_info_t)* info
    );
    ulong fido_cbor_info_uv_modality(
        const(fido_cbor_info_t)* info
    );
    long fido_cbor_info_rk_remaining(
        const(fido_cbor_info_t)* info
    );

    fido_cred_t* fido_cred_new();
    void fido_cred_free(fido_cred_t** cred);
    int fido_cred_set_type(fido_cred_t* cred, int coseType);
    int fido_cred_set_clientdata_hash(
        fido_cred_t* cred,
        const(ubyte)* data,
        size_t length
    );
    int fido_cred_set_rp(
        fido_cred_t* cred,
        const(char)* id,
        const(char)* name
    );
    int fido_cred_set_user(
        fido_cred_t* cred,
        const(ubyte)* id,
        size_t idLength,
        const(char)* name,
        const(char)* displayName,
        const(char)* icon
    );
    int fido_cred_set_extensions(
        fido_cred_t* cred,
        int flags
    );
    int fido_cred_set_rk(
        fido_cred_t* cred,
        FidoOpt value
    );
    int fido_cred_set_uv(
        fido_cred_t* cred,
        FidoOpt value
    );
    int fido_cred_set_prot(
        fido_cred_t* cred,
        int protection
    );
    int fido_dev_make_cred(
        fido_dev_t* dev,
        fido_cred_t* cred,
        const(char)* pin
    );
    const(ubyte)* fido_cred_id_ptr(
        const(fido_cred_t)* cred
    );
    size_t fido_cred_id_len(
        const(fido_cred_t)* cred
    );

    fido_assert_t* fido_assert_new();
    void fido_assert_free(fido_assert_t** assertion);
    int fido_assert_set_clientdata_hash(
        fido_assert_t* assertion,
        const(ubyte)* data,
        size_t length
    );
    int fido_assert_set_rp(
        fido_assert_t* assertion,
        const(char)* id
    );
    int fido_assert_allow_cred(
        fido_assert_t* assertion,
        const(ubyte)* credentialId,
        size_t credentialIdLength
    );
    int fido_assert_set_extensions(
        fido_assert_t* assertion,
        int flags
    );
    int fido_assert_set_hmac_salt(
        fido_assert_t* assertion,
        const(ubyte)* salt,
        size_t saltLength
    );
    int fido_assert_set_up(
        fido_assert_t* assertion,
        FidoOpt value
    );
    int fido_assert_set_uv(
        fido_assert_t* assertion,
        FidoOpt value
    );
    int fido_dev_get_assert(
        fido_dev_t* dev,
        fido_assert_t* assertion,
        const(char)* pin
    );
    size_t fido_assert_count(
        const(fido_assert_t)* assertion
    );
    const(ubyte)* fido_assert_hmac_secret_ptr(
        const(fido_assert_t)* assertion,
        size_t index
    );
    size_t fido_assert_hmac_secret_len(
        const(fido_assert_t)* assertion,
        size_t index
    );
    ubyte fido_assert_flags(
        const(fido_assert_t)* assertion,
        size_t index
    );
}
