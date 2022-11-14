#include "protocol.h"

#include <string.h>
#include <assert.h>

#include "curve.h"
#include "signal_protocol_internal.h"
#include "WhisperTextProtocol.pb-c.h"
#include "OMEMO.pb-c.h"

#define SIGNAL_MESSAGE_MAC_LENGTH 8
#define OMEMO_MESSAGE_MAC_LENGTH 16
#define SIGNATURE_LENGTH 64

struct ciphertext_message
{
    signal_type_base base;
    int message_type;
    signal_context *global_context;
    signal_buffer *serialized;
};

struct signal_message
{
    ciphertext_message base_message;
    uint8_t message_version;
    ec_public_key *sender_ratchet_key;
    uint32_t counter;
    uint32_t previous_counter;
    signal_buffer *ciphertext;
    signal_buffer *authenticated_part;
    signal_buffer *mac;
};

struct pre_key_signal_message
{
    ciphertext_message base_message;
    uint8_t version;
    uint32_t registration_id;
    int has_pre_key_id;
    uint32_t pre_key_id;
    uint32_t signed_pre_key_id;
    ec_public_key *base_key;
    ec_public_key *identity_key;
    signal_message *message;
};

struct sender_key_message
{
    ciphertext_message base_message;
    uint8_t message_version;
    uint32_t key_id;
    uint32_t iteration;
    signal_buffer *ciphertext;
};

struct sender_key_distribution_message
{
    ciphertext_message base_message;
    uint32_t id;
    uint32_t iteration;
    signal_buffer *chain_key;
    ec_public_key *signature_key;
};

static int signal_message_serialize(signal_buffer **buffer, const signal_message *message);
static int signal_message_serialize_omemo(signal_buffer **buffer, const signal_message *message);
static int signal_message_serialize_omemo_authenticated(signal_buffer **buffer, const signal_message *message);
static int signal_message_get_mac(signal_buffer **buffer,
        uint8_t message_version,
        ec_public_key *sender_identity_key,
        ec_public_key *receiver_identity_key,
        const uint8_t *mac_key, size_t mac_key_len,
        const uint8_t *serialized, size_t serialized_len,
        uint8_t sender_is_alice,
        signal_context *global_context);

static int pre_key_signal_message_serialize(signal_buffer **buffer, const pre_key_signal_message *message);
static int pre_key_signal_message_serialize_omemo(signal_buffer **buffer, const pre_key_signal_message *message);

static int sender_key_message_serialize(signal_buffer **buffer, const sender_key_message *message, ec_private_key *signature_key, signal_context *global_context);
static int sender_key_distribution_message_serialize(signal_buffer **buffer, const sender_key_distribution_message *message);

/*------------------------------------------------------------------------*/

int ciphertext_message_get_type(const ciphertext_message *message)
{
    assert(message);
    return message->message_type;
}

signal_buffer *ciphertext_message_get_serialized(const ciphertext_message *message)
{
    assert(message);
    return message->serialized;
}

/*------------------------------------------------------------------------*/

int signal_message_create(signal_message **message, uint8_t message_version,
        const uint8_t *mac_key, size_t mac_key_len,
        ec_public_key *sender_ratchet_key, uint32_t counter, uint32_t previous_counter,
        const uint8_t *ciphertext, size_t ciphertext_len,
        ec_public_key *sender_identity_key, ec_public_key *receiver_identity_key,
        uint8_t sender_is_alice,
        signal_context *global_context)
{
    int result = 0;
    signal_buffer *message_buf = 0;
    signal_message *result_message = 0;

    assert(global_context);

    result_message = malloc(sizeof(signal_message));
    if(!result_message) {
        return SG_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(signal_message));
    SIGNAL_INIT(result_message, signal_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SIGNAL_TYPE;
    result_message->base_message.global_context = global_context;

    SIGNAL_REF(sender_ratchet_key);
    result_message->sender_ratchet_key = sender_ratchet_key;

    result_message->counter = counter;
    result_message->previous_counter = previous_counter;

    result_message->ciphertext = signal_buffer_create(ciphertext, ciphertext_len);
    if(!result_message->ciphertext) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_message->message_version = message_version;

    result = signal_message_serialize(&message_buf, result_message);
    if(result < 0) {
        goto complete;
    }

    result = signal_message_get_mac(&(result_message->mac),
            message_version, sender_identity_key, receiver_identity_key,
            mac_key, mac_key_len,
            signal_buffer_data(message_buf),
            signal_buffer_len(message_buf),
            sender_is_alice,
            global_context);
    if(result < 0) {
        goto complete;
    }

    if (message_version == 4) {
        result_message->authenticated_part = message_buf;
        message_buf = 0;
        signal_message_serialize_omemo_authenticated(&(result_message->base_message.serialized), result_message);
        if (!result_message->base_message.serialized) {
            result = SG_ERR_NOMEM;
        }
    } else {
        result_message->base_message.serialized = signal_buffer_append(
                message_buf,
                signal_buffer_data(result_message->mac),
                signal_buffer_len(result_message->mac));
        if(result_message->base_message.serialized) {
            message_buf = 0;
        }
        else {
            result = SG_ERR_NOMEM;
        }
    }

complete:
    if(message_buf) {
        signal_buffer_free(message_buf);
    }
    if(result >= 0) {
        result = 0;
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

static int signal_message_serialize(signal_buffer **buffer, const signal_message *message)
{
    if (message->message_version >= 4) return signal_message_serialize_omemo(buffer, message);
    int result = 0;
    size_t result_size = 0;
    signal_buffer *result_buf = 0;
    Textsecure__SignalMessage message_structure = TEXTSECURE__SIGNAL_MESSAGE__INIT;
    size_t len = 0;
    uint8_t *data = 0;

    uint8_t version = (message->message_version << 4) | CIPHERTEXT_CURRENT_VERSION;

    result = ec_public_key_serialize_protobuf(&message_structure.ratchetkey, message->sender_ratchet_key);
    if(result < 0) {
        goto complete;
    }
    message_structure.has_ratchetkey = 1;

    message_structure.counter = message->counter;
    message_structure.has_counter = 1;

    message_structure.previouscounter = message->previous_counter;
    message_structure.has_previouscounter = 1;

    message_structure.ciphertext.data = signal_buffer_data(message->ciphertext);
    message_structure.ciphertext.len = signal_buffer_len(message->ciphertext);
    message_structure.has_ciphertext = 1;

    len = textsecure__signal_message__get_packed_size(&message_structure);

    result_buf = signal_buffer_alloc(len + 1);
    if(!result_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    data = signal_buffer_data(result_buf);
    data[0] = version;

    result_size = textsecure__signal_message__pack(&message_structure, data + 1);
    if(result_size != len) {
        signal_buffer_free(result_buf);
        result = SG_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

complete:
    if(message_structure.ratchetkey.data) {
        free(message_structure.ratchetkey.data);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

static int signal_message_serialize_omemo(signal_buffer **buffer, const signal_message *message)
{
    int result = 0;
    size_t result_size = 0;
    signal_buffer *result_buf = 0;
    Omemo__OMEMOMessage message_structure = OMEMO__OMEMOMESSAGE__INIT;
    size_t len = 0;

    result = ec_public_key_serialize_protobuf_mont(&message_structure.dh_pub, message->sender_ratchet_key);
    if(result < 0) {
        goto complete;
    }

    message_structure.n = message->counter;

    message_structure.pn = message->previous_counter;

    message_structure.ciphertext.data = signal_buffer_data(message->ciphertext);
    message_structure.ciphertext.len = signal_buffer_len(message->ciphertext);
    message_structure.has_ciphertext = 1;

    len = omemo__omemomessage__get_packed_size(&message_structure);

    result_buf = signal_buffer_alloc(len);
    if(!result_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_size = omemo__omemomessage__pack(&message_structure, signal_buffer_data(result_buf));
    if(result_size != len) {
        signal_buffer_free(result_buf);
        result = SG_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

    complete:
    if(message_structure.dh_pub.data) {
        free(message_structure.dh_pub.data);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

static int signal_message_serialize_omemo_authenticated(signal_buffer **buffer, const signal_message *message)
{
    assert(message->authenticated_part);
    assert(message->mac);
    int result = 0;
    size_t result_size = 0;
    signal_buffer *result_buf = 0;
    Omemo__OMEMOAuthenticatedMessage message_structure = OMEMO__OMEMOAUTHENTICATED_MESSAGE__INIT;
    size_t len = 0;

    message_structure.message.data = signal_buffer_data(message->authenticated_part);
    message_structure.message.len = signal_buffer_len(message->authenticated_part);

    message_structure.mac.data = signal_buffer_data(message->mac);
    message_structure.mac.len = signal_buffer_len(message->mac);

    len = omemo__omemoauthenticated_message__get_packed_size(&message_structure);

    result_buf = signal_buffer_alloc(len);
    if(!result_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_size = omemo__omemoauthenticated_message__pack(&message_structure, signal_buffer_data(result_buf));
    if(result_size != len) {
        signal_buffer_free(result_buf);
        result = SG_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

    complete:
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int signal_message_deserialize(signal_message **message, const uint8_t *data, size_t len, signal_context *global_context)
{
    int result = 0;
    signal_message *result_message = 0;
    Textsecure__SignalMessage *message_structure = 0;
    uint8_t version = 0;
    uint8_t *ciphertext_data = 0;
    uint8_t *serialized_data = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;

    assert(global_context);

    if(!data || len <= 1 + SIGNAL_MESSAGE_MAC_LENGTH) {
        result = SG_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;

    /* Set some pointers and lengths for the sections of the raw data */
    message_data = data + 1;
    message_len = len - 1 - SIGNAL_MESSAGE_MAC_LENGTH;

    if(version <= CIPHERTEXT_UNSUPPORTED_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unsupported legacy version: %d", version);
        result = SG_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unknown version: %d", version);
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    message_structure = textsecure__signal_message__unpack(0, message_len, message_data);
    if(!message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!message_structure->has_ciphertext
            || !message_structure->has_counter
            || !message_structure->has_ratchetkey) {
        signal_log(global_context, SG_LOG_WARNING, "Incomplete message");
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(signal_message));
    if(!result_message) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(signal_message));
    SIGNAL_INIT(result_message, signal_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SIGNAL_TYPE;
    result_message->base_message.global_context = global_context;

    result = curve_decode_point(&result_message->sender_ratchet_key,
            message_structure->ratchetkey.data, message_structure->ratchetkey.len, global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->message_version = version;
    result_message->counter = message_structure->counter;
    result_message->previous_counter = message_structure->previouscounter;

    result_message->ciphertext = signal_buffer_alloc(message_structure->ciphertext.len);
    if(!result_message->ciphertext) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    ciphertext_data = signal_buffer_data(result_message->ciphertext);
    memcpy(ciphertext_data, message_structure->ciphertext.data, message_structure->ciphertext.len);

    result_message->base_message.serialized = signal_buffer_alloc(len);
    if(!result_message->base_message.serialized) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    serialized_data = signal_buffer_data(result_message->base_message.serialized);
    memcpy(serialized_data, data, len);

complete:
    if(message_structure) {
        textsecure__signal_message__free_unpacked(message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int signal_message_deserialize_omemo(signal_message **message, const uint8_t *data, size_t len, signal_context *global_context)
{
    int result = 0;
    signal_message *result_message = 0;
    Omemo__OMEMOAuthenticatedMessage *authenticated_message_structure = 0;
    Omemo__OMEMOMessage *message_structure = 0;

    assert(global_context);

    authenticated_message_structure = omemo__omemoauthenticated_message__unpack(0, len, data);

    if(!authenticated_message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    message_structure = omemo__omemomessage__unpack(0, authenticated_message_structure->message.len, authenticated_message_structure->message.data);

    if(!message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!message_structure->has_ciphertext) {
        signal_log(global_context, SG_LOG_WARNING, "Incomplete message");
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(signal_message));
    if(!result_message) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(signal_message));
    SIGNAL_INIT(result_message, signal_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SIGNAL_TYPE;
    result_message->base_message.global_context = global_context;

    result = curve_decode_point_mont(&result_message->sender_ratchet_key, message_structure->dh_pub.data, message_structure->dh_pub.len, global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->message_version = 4;
    result_message->counter = message_structure->n;
    result_message->previous_counter = message_structure->pn;

    result_message->authenticated_part = signal_buffer_alloc(authenticated_message_structure->message.len);
    if(!result_message->authenticated_part) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memcpy(signal_buffer_data(result_message->authenticated_part), authenticated_message_structure->message.data, authenticated_message_structure->message.len);

    result_message->ciphertext = signal_buffer_alloc(message_structure->ciphertext.len);
    if(!result_message->ciphertext) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memcpy(signal_buffer_data(result_message->ciphertext), message_structure->ciphertext.data, message_structure->ciphertext.len);

    result_message->mac = signal_buffer_alloc(authenticated_message_structure->mac.len);
    if(!result_message->mac) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memcpy(signal_buffer_data(result_message->mac), authenticated_message_structure->mac.data, authenticated_message_structure->mac.len);

    result_message->base_message.serialized = signal_buffer_alloc(len);
    if(!result_message->base_message.serialized) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memcpy(signal_buffer_data(result_message->base_message.serialized), data, len);

    complete:
    if(message_structure) {
        omemo__omemomessage__free_unpacked(message_structure, 0);
    }
    if(authenticated_message_structure) {
        omemo__omemoauthenticated_message__free_unpacked(authenticated_message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int signal_message_copy(signal_message **message, signal_message *other_message, signal_context *global_context)
{
    int result = 0;
    signal_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    if (other_message->message_version >= 4) {
        result = signal_message_deserialize_omemo(
                &result_message,
                signal_buffer_data(other_message->base_message.serialized),
                signal_buffer_len(other_message->base_message.serialized),
                global_context);
    } else {
        result = signal_message_deserialize(
                &result_message,
                signal_buffer_data(other_message->base_message.serialized),
                signal_buffer_len(other_message->base_message.serialized),
                global_context);
    }
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

ec_public_key *signal_message_get_sender_ratchet_key(const signal_message *message)
{
    assert(message);
    return message->sender_ratchet_key;
}

uint8_t signal_message_get_message_version(const signal_message *message)
{
    assert(message);
    return message->message_version;
}

uint32_t signal_message_get_counter(const signal_message *message)
{
    assert(message);
    return message->counter;
}

signal_buffer *signal_message_get_body(const signal_message *message)
{
    assert(message);
    return message->ciphertext;
}

int signal_message_verify_mac(signal_message *message,
        ec_public_key *sender_identity_key,
        ec_public_key *receiver_identity_key,
        const uint8_t *mac_key, size_t mac_key_len,
        uint8_t sender_is_alice,
        signal_context *global_context)
{
    int result = 0;
    signal_buffer *our_mac_buffer = 0;
    uint8_t *serialized_data = 0;
    size_t serialized_len = 0;
    uint8_t *serialized_message_data = 0;
    size_t serialized_message_len = 0;
    uint8_t *their_mac_data = 0;
    size_t their_mac_len = 0;
    uint8_t *our_mac_data = 0;
    size_t our_mac_len = 0;

    assert(message);
    assert(message->base_message.serialized);

    if (message->message_version < 4) {
        /* Set some pointers and lengths for the sections of the raw data */
        serialized_data = signal_buffer_data(message->base_message.serialized);
        serialized_len = signal_buffer_len(message->base_message.serialized);
        serialized_message_data = serialized_data;
        serialized_message_len = serialized_len - SIGNAL_MESSAGE_MAC_LENGTH;
        their_mac_data = serialized_data + serialized_message_len;
        their_mac_len = SIGNAL_MESSAGE_MAC_LENGTH;
    } else {
        /* In OMEMO we already decoded the MAC properly */
        their_mac_data = signal_buffer_data(message->mac);
        their_mac_len = signal_buffer_len(message->mac);
        serialized_message_data = signal_buffer_data(message->authenticated_part);
        serialized_message_len = signal_buffer_len(message->authenticated_part);
    }

    result = signal_message_get_mac(&our_mac_buffer,
            message->message_version,
            sender_identity_key, receiver_identity_key,
            mac_key, mac_key_len,
            serialized_message_data, serialized_message_len,
            sender_is_alice,
            message->base_message.global_context);
    if(result < 0) {
        goto complete;
    }

    our_mac_data = signal_buffer_data(our_mac_buffer);
    our_mac_len = signal_buffer_len(our_mac_buffer);
    if(our_mac_len != their_mac_len) {
        signal_log(global_context, SG_LOG_WARNING, "MAC length mismatch: %d != %d", our_mac_len, their_mac_len);
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    if(signal_constant_memcmp(our_mac_data, their_mac_data, our_mac_len) == 0) {
        result = 1;
    }
    else {
        signal_log(global_context, SG_LOG_NOTICE, "Bad MAC");
        result = 0;
    }

complete:
    if(our_mac_buffer) {
        signal_buffer_free(our_mac_buffer);
    }
    return result;
}

static int signal_message_get_mac(signal_buffer **buffer,
        uint8_t message_version,
        ec_public_key *sender_identity_key,
        ec_public_key *receiver_identity_key,
        const uint8_t *mac_key, size_t mac_key_len,
        const uint8_t *serialized, size_t serialized_len,
        uint8_t sender_is_alice,
        signal_context *global_context)
{
    int result = 0;
    void *hmac_context;
    signal_buffer *first_key_buffer = 0;
    signal_buffer *second_key_buffer = 0;
    signal_buffer *full_mac_buffer = 0;
    signal_buffer *result_buf = 0;
    uint8_t *result_data = 0;
    size_t mac_length = message_version < 4 ? SIGNAL_MESSAGE_MAC_LENGTH : OMEMO_MESSAGE_MAC_LENGTH;

    assert(global_context);

    result = signal_hmac_sha256_init(global_context,
            &hmac_context, mac_key, mac_key_len);
    if(result < 0) {
        goto complete;
    }

    if(message_version >= 3) {
        if (message_version >= 4) {
            if (sender_is_alice) {
                first_key_buffer = ec_public_key_get_ed(sender_identity_key);
            } else {
                first_key_buffer = ec_public_key_get_ed(receiver_identity_key);
            }
        } else {
            result = ec_public_key_serialize(&first_key_buffer, sender_identity_key);
        }
        if(first_key_buffer == 0 || result < 0) {
            goto complete;
        }

        result = signal_hmac_sha256_update(global_context, hmac_context,
                signal_buffer_data(first_key_buffer),
                signal_buffer_len(first_key_buffer));
        if(result < 0) {
            goto complete;
        }

        if (message_version >= 4) {
            if (sender_is_alice) {
                second_key_buffer = ec_public_key_get_ed(receiver_identity_key);
            } else {
                second_key_buffer = ec_public_key_get_ed(sender_identity_key);
            }
        } else {
            result = ec_public_key_serialize(&second_key_buffer, receiver_identity_key);
        }
        if(second_key_buffer == 0 || result < 0) {
            goto complete;
        }

        result = signal_hmac_sha256_update(global_context, hmac_context,
                signal_buffer_data(second_key_buffer),
                signal_buffer_len(second_key_buffer));
        if(result < 0) {
            goto complete;
        }
    }

    result = signal_hmac_sha256_update(global_context, hmac_context,
        serialized, serialized_len);
    if(result < 0) {
        goto complete;
    }

    result = signal_hmac_sha256_final(global_context,
            hmac_context, &full_mac_buffer);
    if(result < 0 || signal_buffer_len(full_mac_buffer) < mac_length) {
        if(result >= 0) { result = SG_ERR_UNKNOWN; }
        goto complete;
    }

    result_buf = signal_buffer_alloc(mac_length);
    if(!result_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_data = signal_buffer_data(result_buf);
    memcpy(result_data, signal_buffer_data(full_mac_buffer), mac_length);

complete:
    signal_hmac_sha256_cleanup(global_context, hmac_context);
    signal_buffer_free(first_key_buffer);
    signal_buffer_free(second_key_buffer);
    signal_buffer_free(full_mac_buffer);
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int signal_message_is_legacy(const uint8_t *data, size_t len)
{
    return data && len >= 1 && ((data[0] & 0xF0) >> 4) <= CIPHERTEXT_UNSUPPORTED_VERSION;
}

void signal_message_destroy(signal_type_base *type)
{
    signal_message *message = (signal_message *)type;

    if(message->base_message.serialized) {
        signal_buffer_free(message->base_message.serialized);
    }
    SIGNAL_UNREF(message->sender_ratchet_key);
    if(message->ciphertext) {
        signal_buffer_free(message->ciphertext);
    }
    if(message->authenticated_part) {
        signal_buffer_free(message->authenticated_part);
    }
    if(message->mac) {
        signal_buffer_free(message->mac);
    }
    free(message);
}

/*------------------------------------------------------------------------*/

int pre_key_signal_message_create(pre_key_signal_message **pre_key_message,
        uint8_t message_version, uint32_t registration_id, const uint32_t *pre_key_id,
        uint32_t signed_pre_key_id, ec_public_key *base_key, ec_public_key *identity_key,
        signal_message *message,
        signal_context *global_context)
{
    int result = 0;
    pre_key_signal_message *result_message = 0;

    assert(global_context);

    result_message = malloc(sizeof(pre_key_signal_message));

    if(!result_message) {
        return SG_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(pre_key_signal_message));
    SIGNAL_INIT(result_message, pre_key_signal_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_PREKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->version = message_version;
    result_message->registration_id = registration_id;
    if(pre_key_id) {
        result_message->has_pre_key_id = 1;
        result_message->pre_key_id = *pre_key_id;
    }
    result_message->signed_pre_key_id = signed_pre_key_id;

    SIGNAL_REF(base_key);
    result_message->base_key = base_key;

    SIGNAL_REF(identity_key);
    result_message->identity_key = identity_key;

    SIGNAL_REF(message);
    result_message->message = message;

    result = pre_key_signal_message_serialize(&result_message->base_message.serialized, result_message);

    if(result >= 0) {
        result = 0;
        *pre_key_message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

static int pre_key_signal_message_serialize(signal_buffer **buffer, const pre_key_signal_message *message)
{
    if (message->version >= 4) return pre_key_signal_message_serialize_omemo(buffer, message);
    int result = 0;
    size_t result_size = 0;
    signal_buffer *result_buf = 0;
    Textsecure__PreKeySignalMessage message_structure = TEXTSECURE__PRE_KEY_SIGNAL_MESSAGE__INIT;
    signal_buffer *inner_message_buffer = 0;
    size_t len = 0;
    uint8_t *data = 0;

    uint8_t version = (message->version << 4) | CIPHERTEXT_CURRENT_VERSION;

    message_structure.registrationid = message->registration_id;
    message_structure.has_registrationid = 1;

    if(message->has_pre_key_id) {
        message_structure.prekeyid = message->pre_key_id;
        message_structure.has_prekeyid = 1;
    }

    message_structure.signedprekeyid = message->signed_pre_key_id;
    message_structure.has_signedprekeyid = 1;

    result = ec_public_key_serialize_protobuf(&message_structure.basekey, message->base_key);
    if(result < 0) {
        goto complete;
    }
    message_structure.has_basekey = 1;

    result = ec_public_key_serialize_protobuf(&message_structure.identitykey, message->identity_key);
    if(result < 0) {
        goto complete;
    }
    message_structure.has_identitykey = 1;

    inner_message_buffer = message->message->base_message.serialized;
    message_structure.message.data = signal_buffer_data(inner_message_buffer);
    message_structure.message.len = signal_buffer_len(inner_message_buffer);
    message_structure.has_message = 1;

    len = textsecure__pre_key_signal_message__get_packed_size(&message_structure);

    result_buf = signal_buffer_alloc(len + 1);
    if(!result_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    data = signal_buffer_data(result_buf);
    data[0] = version;

    result_size = textsecure__pre_key_signal_message__pack(&message_structure, data + 1);
    if(result_size != len) {
        signal_buffer_free(result_buf);
        result = SG_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

complete:
    if(message_structure.basekey.data) {
        free(message_structure.basekey.data);
    }
    if(message_structure.identitykey.data) {
        free(message_structure.identitykey.data);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

static int pre_key_signal_message_serialize_omemo(signal_buffer **buffer, const pre_key_signal_message *message)
{
    int result = 0;
    size_t result_size = 0;
    signal_buffer *result_buf = 0;
    Omemo__OMEMOKeyExchange message_structure = OMEMO__OMEMOKEY_EXCHANGE__INIT;
    signal_buffer *inner_message_buffer = 0;
    size_t len = 0;

    message_structure.pk_id = message->pre_key_id;
    message_structure.spk_id = message->signed_pre_key_id;

    result = ec_public_key_serialize_protobuf_mont(&message_structure.ek, message->base_key);
    if(result < 0) {
        goto complete;
    }

    result = ec_public_key_serialize_protobuf_ed(&message_structure.ik, message->identity_key);
    if(result < 0) {
        goto complete;
    }

    inner_message_buffer = message->message->base_message.serialized;
    message_structure.message.data = signal_buffer_data(inner_message_buffer);
    message_structure.message.len = signal_buffer_len(inner_message_buffer);

    len = omemo__omemokey_exchange__get_packed_size(&message_structure);

    result_buf = signal_buffer_alloc(len);
    if(!result_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_size = omemo__omemokey_exchange__pack(&message_structure, signal_buffer_data(result_buf));
    if(result_size != len) {
        signal_buffer_free(result_buf);
        result = SG_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

    complete:
    if(message_structure.ek.data) {
        free(message_structure.ek.data);
    }
    if(message_structure.ik.data) {
        free(message_structure.ik.data);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int pre_key_signal_message_deserialize(pre_key_signal_message **message,
        const uint8_t *data, size_t len,
        signal_context *global_context)
{
    int result = 0;
    pre_key_signal_message *result_message = 0;
    Textsecure__PreKeySignalMessage *message_structure = 0;
    uint8_t version = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;
    uint8_t *serialized_data = 0;

    assert(global_context);

    if(!data || len <= 1) {
        result = SG_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;

    /* Set some pointers and lengths for the sections of the raw data */
    message_data = data + 1;
    message_len = len - 1;

    if(version < CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unsupported legacy version: %d", version);
        result = SG_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unknown version: %d", version);
        result = SG_ERR_INVALID_VERSION;
        goto complete;
    }

    message_structure = textsecure__pre_key_signal_message__unpack(0, message_len, message_data);
    if(!message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!message_structure->has_signedprekeyid ||
            !message_structure->has_basekey ||
            !message_structure->has_identitykey ||
            !message_structure->has_message) {
        signal_log(global_context, SG_LOG_WARNING, "Incomplete message");
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(pre_key_signal_message));
    if(!result_message) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(pre_key_signal_message));
    SIGNAL_INIT(result_message, pre_key_signal_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_PREKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->version = version;

    if(message_structure->has_registrationid) {
        result_message->registration_id = message_structure->registrationid;
    }

    if(message_structure->has_prekeyid) {
        result_message->pre_key_id = message_structure->prekeyid;
        result_message->has_pre_key_id = 1;
    }

    if(message_structure->has_signedprekeyid) {
        result_message->signed_pre_key_id = message_structure->signedprekeyid;
    }

    if(message_structure->has_basekey) {
        result = curve_decode_point_mont(&result_message->base_key,
                message_structure->basekey.data, message_structure->basekey.len, global_context);
        if(result < 0) {
            goto complete;
        }
    }

    if(message_structure->has_identitykey) {
        result = curve_decode_point(&result_message->identity_key,
                message_structure->identitykey.data, message_structure->identitykey.len, global_context);
        if(result < 0) {
            goto complete;
        }
    }

    if(message_structure->has_message) {
        result = signal_message_deserialize(&result_message->message,
                message_structure->message.data,
                message_structure->message.len,
                global_context);
        if(result < 0) {
            goto complete;
        }
        if(result_message->message->message_version != version) {
            signal_log(global_context, SG_LOG_WARNING, "Inner message version mismatch: %d != %d",
                    result_message->message->message_version, version);
            result = SG_ERR_INVALID_VERSION;
            goto complete;
        }
    }

    result_message->base_message.serialized = signal_buffer_alloc(len);
    if(!result_message->base_message.serialized) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    serialized_data = signal_buffer_data(result_message->base_message.serialized);
    memcpy(serialized_data, data, len);

complete:
    if(message_structure) {
        textsecure__pre_key_signal_message__free_unpacked(message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int pre_key_signal_message_deserialize_omemo(pre_key_signal_message **message,
                                       const uint8_t *data, size_t len,
                                       uint32_t registration_id,
                                       signal_context *global_context)
{
    int result = 0;
    pre_key_signal_message *result_message = 0;
    Omemo__OMEMOKeyExchange *message_structure = 0;
    uint8_t *serialized_data = 0;

    assert(global_context);

    message_structure = omemo__omemokey_exchange__unpack(0, len, data);
    if(!message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    result_message = malloc(sizeof(pre_key_signal_message));
    if(!result_message) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(pre_key_signal_message));
    SIGNAL_INIT(result_message, pre_key_signal_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_PREKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->version = 4;
    result_message->registration_id = registration_id;

    result_message->pre_key_id = message_structure->pk_id;
    result_message->has_pre_key_id = 1;

    result_message->signed_pre_key_id = message_structure->spk_id;

    result = curve_decode_point_mont(&result_message->base_key, message_structure->ek.data, message_structure->ek.len, global_context);
    if(result < 0) {
        goto complete;
    }

    result = curve_decode_point(&result_message->identity_key, message_structure->ik.data, message_structure->ik.len, global_context);
    if(result < 0) {
        goto complete;
    }

    result = signal_message_deserialize_omemo(&result_message->message,
                                        message_structure->message.data,
                                        message_structure->message.len,
                                        global_context);
    if(result < 0) {
        goto complete;
    }
    if(result_message->message->message_version != result_message->version) {
        signal_log(global_context, SG_LOG_WARNING, "Inner message version mismatch: %d != %d", result_message->message->message_version, result_message->version);
        result = SG_ERR_INVALID_VERSION;
        goto complete;
    }

    result_message->base_message.serialized = signal_buffer_alloc(len);
    if(!result_message->base_message.serialized) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    serialized_data = signal_buffer_data(result_message->base_message.serialized);
    memcpy(serialized_data, data, len);

    complete:
    if(message_structure) {
        omemo__omemokey_exchange__free_unpacked(message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int pre_key_signal_message_copy(pre_key_signal_message **message, pre_key_signal_message *other_message, signal_context *global_context)
{
    int result = 0;
    pre_key_signal_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    if (other_message->version >= 4) {
        result = pre_key_signal_message_deserialize_omemo(
                &result_message,
                signal_buffer_data(other_message->base_message.serialized),
                signal_buffer_len(other_message->base_message.serialized),
                other_message->registration_id,
                global_context);
    } else {
        result = pre_key_signal_message_deserialize(
                &result_message,
                signal_buffer_data(other_message->base_message.serialized),
                signal_buffer_len(other_message->base_message.serialized),
                global_context);
    }
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

uint8_t pre_key_signal_message_get_message_version(const pre_key_signal_message *message)
{
    assert(message);
    return message->version;
}

ec_public_key *pre_key_signal_message_get_identity_key(const pre_key_signal_message *message)
{
    assert(message);
    return message->identity_key;
}

uint32_t pre_key_signal_message_get_registration_id(const pre_key_signal_message *message)
{
    assert(message);
    return message->registration_id;
}

int pre_key_signal_message_has_pre_key_id(const pre_key_signal_message *message)
{
    assert(message);
    return message->has_pre_key_id;
}

uint32_t pre_key_signal_message_get_pre_key_id(const pre_key_signal_message *message)
{
    assert(message);
    assert(message->has_pre_key_id);
    return message->pre_key_id;
}

uint32_t pre_key_signal_message_get_signed_pre_key_id(const pre_key_signal_message *message)
{
    assert(message);
    return message->signed_pre_key_id;
}

ec_public_key *pre_key_signal_message_get_base_key(const pre_key_signal_message *message)
{
    assert(message);
    return message->base_key;
}

signal_message *pre_key_signal_message_get_signal_message(const pre_key_signal_message *message)
{
    assert(message);
    return message->message;
}

void pre_key_signal_message_destroy(signal_type_base *type)
{
    pre_key_signal_message *message = (pre_key_signal_message *)type;

    if(message->base_message.serialized) {
        signal_buffer_free(message->base_message.serialized);
    }
    SIGNAL_UNREF(message->base_key);
    SIGNAL_UNREF(message->identity_key);
    SIGNAL_UNREF(message->message);
    free(message);
}

int sender_key_message_create(sender_key_message **message,
        uint32_t key_id, uint32_t iteration,
        const uint8_t *ciphertext, size_t ciphertext_len,
        ec_private_key *signature_key,
        signal_context *global_context)
{
    int result = 0;
    sender_key_message *result_message = 0;
    signal_buffer *message_buf = 0;

    assert(global_context);

    result_message = malloc(sizeof(sender_key_message));

    if(!result_message) {
        return SG_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(sender_key_message));
    SIGNAL_INIT(result_message, sender_key_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->message_version = CIPHERTEXT_CURRENT_VERSION;
    result_message->key_id = key_id;
    result_message->iteration = iteration;

    result_message->ciphertext = signal_buffer_create(ciphertext, ciphertext_len);
    if(!result_message->ciphertext) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result = sender_key_message_serialize(&message_buf, result_message, signature_key, global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = message_buf;

complete:
    if(result >= 0) {
        result = 0;
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_message_serialize(signal_buffer **buffer, const sender_key_message *message, ec_private_key *signature_key, signal_context *global_context)
{
    int result = 0;
    uint8_t version = (CIPHERTEXT_CURRENT_VERSION << 4) | CIPHERTEXT_CURRENT_VERSION;
    size_t result_size = 0;
    signal_buffer *result_buf = 0;
    signal_buffer *signature_buf = 0;
    Textsecure__SenderKeyMessage message_structure = TEXTSECURE__SENDER_KEY_MESSAGE__INIT;
    size_t len = 0;
    uint8_t *data = 0;

    message_structure.id = message->key_id;
    message_structure.has_id = 1;

    message_structure.iteration = message->iteration;
    message_structure.has_iteration = 1;

    message_structure.ciphertext.data = signal_buffer_data(message->ciphertext);
    message_structure.ciphertext.len = signal_buffer_len(message->ciphertext);
    message_structure.has_ciphertext = 1;

    len = textsecure__sender_key_message__get_packed_size(&message_structure);

    result_buf = signal_buffer_alloc(sizeof(version) + len + SIGNATURE_LENGTH);
    if(!result_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    data = signal_buffer_data(result_buf);
    data[0] = version;

    result_size = textsecure__sender_key_message__pack(&message_structure, data + sizeof(version));
    if(result_size != len) {
        signal_buffer_free(result_buf);
        result = SG_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

    result = curve_calculate_signature(global_context, &signature_buf, signature_key,
            data, len + sizeof(version));
    if(result < 0) {
        if(result == SG_ERR_INVALID_KEY) {
            result = SG_ERR_UNKNOWN;
        }
        goto complete;
    }
    else if(signal_buffer_len(signature_buf) != SIGNATURE_LENGTH) {
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    memcpy(data + sizeof(version) + len, signal_buffer_data(signature_buf), SIGNATURE_LENGTH);

complete:
    signal_buffer_free(signature_buf);
    if(result >= 0) {
        *buffer = result_buf;
    }
    else {
        signal_buffer_free(result_buf);
    }
    return result;
}

int sender_key_message_deserialize(sender_key_message **message,
        const uint8_t *data, size_t len,
        signal_context *global_context)
{
    int result = 0;
    sender_key_message *result_message = 0;
    uint8_t version = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;
    Textsecure__SenderKeyMessage *message_structure = 0;

    assert(global_context);

    if(!data || len <= sizeof(uint8_t) + SIGNATURE_LENGTH) {
        result = SG_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;
    message_data = data + sizeof(uint8_t);
    message_len = len - sizeof(uint8_t) - SIGNATURE_LENGTH;

    if(version < CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Legacy message: %d", version);
        result = SG_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unknown version: %d", version);
        result = SG_ERR_INVALID_VERSION;
        goto complete;
    }

    message_structure = textsecure__sender_key_message__unpack(0, message_len, message_data);
    if(!message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!message_structure->has_id
            || !message_structure->has_iteration
            || !message_structure->has_ciphertext) {
        signal_log(global_context, SG_LOG_WARNING, "Incomplete message");
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(sender_key_message));
    if(!result_message) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(sender_key_message));
    SIGNAL_INIT(result_message, sender_key_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->key_id = message_structure->id;
    result_message->iteration = message_structure->iteration;
    result_message->message_version = version;

    result_message->ciphertext = signal_buffer_create(
            message_structure->ciphertext.data,
            message_structure->ciphertext.len);
    if(!result_message->ciphertext) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_message->base_message.serialized = signal_buffer_create(data, len);
    if(!result_message->base_message.serialized) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

complete:
    if(message_structure) {
        textsecure__sender_key_message__free_unpacked(message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_message_copy(sender_key_message **message, sender_key_message *other_message, signal_context *global_context)
{
    int result = 0;
    sender_key_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    result = sender_key_message_deserialize(
            &result_message,
            signal_buffer_data(other_message->base_message.serialized),
            signal_buffer_len(other_message->base_message.serialized),
            global_context);
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

uint32_t sender_key_message_get_key_id(sender_key_message *message)
{
    assert(message);
    return message->key_id;
}

uint32_t sender_key_message_get_iteration(sender_key_message *message)
{
    assert(message);
    return message->iteration;
}

signal_buffer *sender_key_message_get_ciphertext(sender_key_message *message)
{
    assert(message);
    return message->ciphertext;
}

int sender_key_message_verify_signature(sender_key_message *message, ec_public_key *signature_key)
{
    int result = 0;
    uint8_t *data;
    size_t data_len;

    assert(message);

    data = signal_buffer_data(message->base_message.serialized);
    data_len = signal_buffer_len(message->base_message.serialized) - SIGNATURE_LENGTH;

    result = curve_verify_signature(signature_key, data, data_len, data + data_len, SIGNATURE_LENGTH);

    if(result == 0) {
        signal_log(message->base_message.global_context, SG_LOG_ERROR, "Invalid signature!");
        result = SG_ERR_INVALID_MESSAGE;
    }
    else if(result < 0) {
        result = SG_ERR_INVALID_MESSAGE;
    }
    else {
        result = 0;
    }

    return result;
}

void sender_key_message_destroy(signal_type_base *type)
{
    sender_key_message *message = (sender_key_message *)type;

    if(message->base_message.serialized) {
        signal_buffer_free(message->base_message.serialized);
    }
    if(message->ciphertext) {
        signal_buffer_free(message->ciphertext);
    }
    free(message);
}

int sender_key_distribution_message_create(sender_key_distribution_message **message,
        uint32_t id, uint32_t iteration,
        const uint8_t *chain_key, size_t chain_key_len,
        ec_public_key *signature_key,
        signal_context *global_context)
{
    int result = 0;

    sender_key_distribution_message *result_message = 0;
    signal_buffer *message_buf = 0;

    assert(global_context);

    result_message = malloc(sizeof(sender_key_distribution_message));

    if(!result_message) {
        return SG_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(sender_key_distribution_message));
    SIGNAL_INIT(result_message, sender_key_distribution_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->id = id;
    result_message->iteration = iteration;

    result_message->chain_key = signal_buffer_create(chain_key, chain_key_len);
    if(!result_message->chain_key) {
        goto complete;
    }

    SIGNAL_REF(signature_key);
    result_message->signature_key = signature_key;

    result = sender_key_distribution_message_serialize(&message_buf, result_message);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = message_buf;

complete:
    if(result >= 0) {
        result = 0;
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_distribution_message_serialize(signal_buffer **buffer, const sender_key_distribution_message *message)
{
    int result = 0;
    uint8_t version = (CIPHERTEXT_CURRENT_VERSION << 4) | CIPHERTEXT_CURRENT_VERSION;
    size_t result_size = 0;
    signal_buffer *result_buf = 0;
    Textsecure__SenderKeyDistributionMessage message_structure = TEXTSECURE__SENDER_KEY_DISTRIBUTION_MESSAGE__INIT;
    size_t len = 0;
    uint8_t *data = 0;

    message_structure.id = message->id;
    message_structure.has_id = 1;

    message_structure.iteration = message->iteration;
    message_structure.has_iteration = 1;

    message_structure.chainkey.data = signal_buffer_data(message->chain_key);
    message_structure.chainkey.len = signal_buffer_len(message->chain_key);
    message_structure.has_chainkey = 1;

    result = ec_public_key_serialize_protobuf(&message_structure.signingkey, message->signature_key);
    if(result < 0) {
        goto complete;
    }
    message_structure.has_signingkey = 1;

    len = textsecure__sender_key_distribution_message__get_packed_size(&message_structure);

    result_buf = signal_buffer_alloc(sizeof(version) + len);
    if(!result_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    data = signal_buffer_data(result_buf);
    data[0] = version;

    result_size = textsecure__sender_key_distribution_message__pack(&message_structure, data + sizeof(version));
    if(result_size != len) {
        signal_buffer_free(result_buf);
        result = SG_ERR_INVALID_PROTO_BUF;
        result_buf = 0;
        goto complete;
    }

complete:
    if(message_structure.has_signingkey) {
        free(message_structure.signingkey.data);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    else {
        signal_buffer_free(result_buf);
    }
    return result;
}

int sender_key_distribution_message_deserialize(sender_key_distribution_message **message,
        const uint8_t *data, size_t len,
        signal_context *global_context)
{
    int result = 0;
    sender_key_distribution_message *result_message = 0;
    uint8_t version = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;
    Textsecure__SenderKeyDistributionMessage *message_structure = 0;

    assert(global_context);

    if(!data || len <= sizeof(uint8_t)) {
        result = SG_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;
    message_data = data + sizeof(uint8_t);
    message_len = len - sizeof(uint8_t);

    if(version < CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Legacy message: %d", version);
        result = SG_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unknown version: %d", version);
        result = SG_ERR_INVALID_VERSION;
        goto complete;
    }

    message_structure = textsecure__sender_key_distribution_message__unpack(0, message_len, message_data);
    if(!message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!message_structure->has_id
            || !message_structure->has_iteration
            || !message_structure->has_chainkey
            || !message_structure->has_signingkey) {
        signal_log(global_context, SG_LOG_WARNING, "Incomplete message");
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(sender_key_distribution_message));
    if(!result_message) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(sender_key_distribution_message));
    SIGNAL_INIT(result_message, sender_key_distribution_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->id = message_structure->id;
    result_message->iteration = message_structure->iteration;

    result_message->chain_key = signal_buffer_create(
            message_structure->chainkey.data,
            message_structure->chainkey.len);
    if(!result_message->chain_key) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result = curve_decode_point(&result_message->signature_key,
            message_structure->signingkey.data,
            message_structure->signingkey.len,
            global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = signal_buffer_create(data, len);
    if(!result_message->base_message.serialized) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

complete:
    if(message_structure) {
        textsecure__sender_key_distribution_message__free_unpacked(message_structure, 0);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_distribution_message_copy(sender_key_distribution_message **message, sender_key_distribution_message *other_message, signal_context *global_context)
{
    int result = 0;
    sender_key_distribution_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    result = sender_key_distribution_message_deserialize(
            &result_message,
            signal_buffer_data(other_message->base_message.serialized),
            signal_buffer_len(other_message->base_message.serialized),
            global_context);
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

uint32_t sender_key_distribution_message_get_id(sender_key_distribution_message *message)
{
    assert(message);
    return message->id;
}

uint32_t sender_key_distribution_message_get_iteration(sender_key_distribution_message *message)
{
    assert(message);
    return message->iteration;
}

signal_buffer *sender_key_distribution_message_get_chain_key(sender_key_distribution_message *message)
{
    assert(message);
    return message->chain_key;
}

ec_public_key *sender_key_distribution_message_get_signature_key(sender_key_distribution_message *message)
{
    assert(message);
    return message->signature_key;
}

void sender_key_distribution_message_destroy(signal_type_base *type)
{
    sender_key_distribution_message *message = (sender_key_distribution_message *)type;

    if(message->base_message.serialized) {
        signal_buffer_free(message->base_message.serialized);
    }

    if(message->chain_key) {
        signal_buffer_free(message->chain_key);
    }
    SIGNAL_UNREF(message->signature_key);
    free(message);
}
