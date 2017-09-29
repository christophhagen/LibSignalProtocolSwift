//
//  main.c
//
//
//  Created by User on 17.09.17.
//
#include "ch_wrapper.h"

#include <pthread.h>

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>



// MARK: Locking

pthread_mutex_t global_mutex;
pthread_mutexattr_t global_mutex_attr;

void ch_lock(void *user_data) {
    pthread_mutex_lock(&global_mutex);
}

void ch_unlock(void *user_data) {
    pthread_mutex_unlock(&global_mutex);
}

int ch_locking_functions_set(signal_context *global_context) {
    pthread_mutexattr_init(&global_mutex_attr);
    pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&global_mutex, &global_mutex_attr);

    return signal_context_set_locking_functions(global_context, ch_lock, ch_unlock);
}

void ch_locking_functions_destroy(void) {
    pthread_mutex_destroy(&global_mutex);
    pthread_mutexattr_destroy(&global_mutex_attr);
}



// MARK: Crypto

/**
 Generate random numbers. This is the way apple recommends to do it, might be too slow to use
 */
static int random_generator(uint8_t *data, size_t len, void *user_data) {
    FILE *fp = fopen("/dev/random", "r");
    if(!fp) {
        return SG_ERR_UNKNOWN;
    }

    size_t n = fread(data, 1, len, fp);

    if(fp) {
        fclose(fp);
    }
    return (n != len) ? SG_ERR_UNKNOWN : 0;
}

/**
 Initialize a HMAC SHA256 context
 */
static int hmac_sha256_init(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data) {
    CCHmacContext *ctx = malloc(sizeof(CCHmacContext));
    if(!ctx) {
        return SG_ERR_NOMEM;
    }

    CCHmacInit(ctx, kCCHmacAlgSHA256, key, key_len);
    *hmac_context = ctx;

    return 0;
}

/**
 Update the HMAC SHA256 context with given data
 */
static int hmac_sha256_update(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data) {
    CCHmacContext *ctx = hmac_context;
    CCHmacUpdate(ctx, data, data_len);
    return 0;
}

/**
 Finalize the HMAC SHA256 context and write it to buffer
 */
static int hmac_sha256_final(void *hmac_context, signal_buffer **output, void *user_data) {
    CCHmacContext *ctx = hmac_context;

    signal_buffer *output_buffer = signal_buffer_alloc(CC_SHA256_DIGEST_LENGTH);
    if(!output_buffer) {
        return SG_ERR_NOMEM;
    }

    CCHmacFinal(ctx, signal_buffer_data(output_buffer));

    *output = output_buffer;

    return 0;
}

/**
 Clean HMAC SHA256 context
 */
static void hmac_sha256_cleanup(void *hmac_context, void *user_data) {
    if(hmac_context) {
        CCHmacContext *ctx = hmac_context;
        free(ctx);
    }
}

/**
 Initialize a digest with SHA512
 */
static int sha512_digest_init(void **digest_context, void *user_data) {
    CC_SHA512_CTX *ctx = malloc(sizeof(CC_SHA512_CTX));
    if(!ctx) {
        return SG_ERR_NOMEM;
    }

    if(CC_SHA512_Init(ctx) != 1) {
        free(ctx);
        return SG_ERR_UNKNOWN;
    }

    *digest_context = ctx;
    return 0;
}

/**
 Update a digest with SHA512 with data
 */
static int sha512_digest_update(void *digest_context, const uint8_t *data, size_t data_len, void *user_data) {
    CC_SHA512_CTX *ctx = digest_context;

    int result = CC_SHA512_Update(ctx, data, (CC_LONG) data_len);
    return (result == 1) ? SG_SUCCESS : SG_ERR_UNKNOWN;
}

/**
 Finalize a digest with SHA512 and write output to buffer
 */
static int sha512_digest_final(void *digest_context, signal_buffer **output, void *user_data) {
    unsigned char md[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512_CTX *ctx = digest_context;

    if (CC_SHA512_Final(md, ctx) != 1) {
        return SG_ERR_UNKNOWN;
    }

    if (CC_SHA512_Init(ctx) != 1){
        return SG_ERR_UNKNOWN;
    }

    signal_buffer *output_buffer = signal_buffer_create(md, CC_SHA512_DIGEST_LENGTH);
    if(!output_buffer) {
        return SG_ERR_NOMEM;
    }

    *output = output_buffer;
    return 0;
}

/**
 Clean a digest with SHA512
 */
void sha512_digest_cleanup(void *digest_context, void *user_data) {
    if(digest_context) {
        CC_SHA512_CTX *ctx = digest_context;
        free(ctx);
    }
}

static int cc_status_to_result(CCCryptorStatus status) {
    switch(status) {
        case kCCSuccess:
            return SG_SUCCESS;
        case kCCParamError:
        case kCCBufferTooSmall:
            return SG_ERR_INVAL;
        case kCCMemoryFailure:
            return SG_ERR_NOMEM;
        case kCCAlignmentError:
        case kCCDecodeError:
        case kCCUnimplemented:
        case kCCOverflow:
        case kCCRNGFailure:
        case kCCUnspecifiedError:
        case kCCCallSequenceError:
        default:
            return SG_ERR_UNKNOWN;
    }
}

/**
 Complete encrypt and decrypt process
 */
static void completeCrypt(CCCryptorRef ref, uint8_t *out_buf) {
    if(ref) {
        CCCryptorRelease(ref);
    }
    if(out_buf) {
        free(out_buf);
    }
}

/**
 Encrypt plaintext with a given cipher, key, and iv
 */
static int ch_encrypt(signal_buffer **output,
                      int cipher,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *plaintext, size_t plaintext_len,
                      void *user_data) {

    uint8_t *out_buf = 0;
    CCCryptorStatus status = kCCSuccess;
    CCCryptorRef ref = 0;

    if(cipher == SG_CIPHER_AES_CBC_PKCS5) {
        status = CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, key_len, iv, &ref);
    }
    else if(cipher == SG_CIPHER_AES_CTR_NOPADDING) {
        status = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding,
                                         iv, key, key_len, 0, 0, 0, kCCModeOptionCTR_BE, &ref);
    }
    else {
        status = kCCParamError;
    }
    if(status != kCCSuccess) {
        completeCrypt(ref, out_buf);
        return cc_status_to_result(status);
    }

    size_t available_len = CCCryptorGetOutputLength(ref, plaintext_len, 1);
    out_buf = malloc(available_len);
    if(!out_buf) {
        fprintf(stderr, "cannot allocate output buffer\n");
        completeCrypt(ref, out_buf);
        return SG_ERR_NOMEM;
    }

    size_t update_moved_len = 0;
    status = CCCryptorUpdate(ref, plaintext, plaintext_len, out_buf, available_len, &update_moved_len);
    if(status != kCCSuccess) {
        completeCrypt(ref, out_buf);
        return cc_status_to_result(status);
    }

    size_t final_moved_len = 0;
    status = CCCryptorFinal(ref, out_buf + update_moved_len, available_len - update_moved_len, &final_moved_len);
    if(status != kCCSuccess) {
        completeCrypt(ref, out_buf);
        return cc_status_to_result(status);
    }

    signal_buffer *output_buffer = signal_buffer_create(out_buf, update_moved_len + final_moved_len);
    if(!output_buffer) {
        completeCrypt(ref, out_buf);
        return SG_ERR_NOMEM;
    }

    *output = output_buffer;
    completeCrypt(ref, out_buf);
    return 0;
}

/**
 Decrypt plaintext with a given cipher, key, and iv
 */
static int ch_decrypt(signal_buffer **output,
                      int cipher,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      void *user_data) {
    uint8_t *out_buf = 0;
    CCCryptorStatus status = kCCSuccess;
    CCCryptorRef ref = 0;

    if(cipher == SG_CIPHER_AES_CBC_PKCS5) {
        status = CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, key_len, iv, &ref);
    }
    else if(cipher == SG_CIPHER_AES_CTR_NOPADDING) {
        status = CCCryptorCreateWithMode(kCCDecrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding,
                                         iv, key, key_len, 0, 0, 0, kCCModeOptionCTR_BE, &ref);
    }
    else {
        status = kCCParamError;
    }
    if(status != kCCSuccess) {
        completeCrypt(ref, out_buf);
        return cc_status_to_result(status);
    }

    out_buf = malloc(sizeof(uint8_t) * ciphertext_len);
    if(!out_buf) {
        fprintf(stderr, "cannot allocate output buffer\n");
        completeCrypt(ref, out_buf);
        return SG_ERR_UNKNOWN;
    }

    size_t update_moved_len = 0;
    status = CCCryptorUpdate(ref, ciphertext, ciphertext_len, out_buf, ciphertext_len, &update_moved_len);
    if(status != kCCSuccess) {
        completeCrypt(ref, out_buf);
        return cc_status_to_result(status);
    }

    size_t final_moved_len = 0;
    status = CCCryptorFinal(ref, out_buf + update_moved_len, ciphertext_len - update_moved_len, &final_moved_len);
    if(status != kCCSuccess) {
        completeCrypt(ref, out_buf);
        return cc_status_to_result(status);
    }

    signal_buffer *output_buffer = signal_buffer_create(out_buf, update_moved_len + final_moved_len);
    if(!output_buffer) {
        completeCrypt(ref, out_buf);
        return SG_ERR_NOMEM;
    }

    *output = output_buffer;
    completeCrypt(ref, out_buf);
    return 0;
}

/**
 Set the callback functions for the context

 @param context The global Signal Protocol context

 @return 0 on success, negative on error
 */
int ch_crypto_provider_set(signal_context *context) {
    signal_crypto_provider provider = {
        .random_func = random_generator,
        .hmac_sha256_init_func = hmac_sha256_init,
        .hmac_sha256_update_func = hmac_sha256_update,
        .hmac_sha256_final_func = hmac_sha256_final,
        .hmac_sha256_cleanup_func = hmac_sha256_cleanup,
        .sha512_digest_init_func = sha512_digest_init,
        .sha512_digest_update_func = sha512_digest_update,
        .sha512_digest_final_func = sha512_digest_final,
        .sha512_digest_cleanup_func = sha512_digest_cleanup,
        .encrypt_func = ch_encrypt,
        .decrypt_func = ch_decrypt,
        .user_data = 0
    };

    return signal_context_set_crypto_provider(context, &provider);
}
