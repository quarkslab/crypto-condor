#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/core_names.h"

int generic_sign(char *alg, uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, int det);

int generic_verify(char *alg, const uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size);

int CC_SLHDSA_sha2_128s_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHA2-128s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_sha2_192s_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHA2-192s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_sha2_256s_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHA2-256s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_sha2_128f_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHA2-128f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_sha2_192f_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHA2-192f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_sha2_256f_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHA2-256f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_shake_128s_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHAKE-128s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_shake_192s_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHAKE-192s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_shake_256s_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHAKE-256s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_shake_128f_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHAKE-128f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_shake_192f_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHAKE-192f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_shake_256f_sign_pure_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, const char *ph, size_t ph_size) {
    return generic_sign("SLH-DSA-SHAKE-256f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, 1);
}

int CC_SLHDSA_sha2_128s_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHA2-128s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_sha2_192s_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHA2-192s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_sha2_256s_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHA2-256s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_sha2_128f_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHA2-128f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_sha2_192f_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHA2-192f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_sha2_256f_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHA2-256f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_shake_128s_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHAKE-128s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_shake_192s_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHAKE-192s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_shake_256s_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHAKE-256s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_shake_128f_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHAKE-128f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_shake_192f_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHAKE-192f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_shake_256f_verify_pure(const uint8_t *sig, size_t sig_size,
             const uint8_t *msg, size_t msg_size,
             const uint8_t *ctx, size_t ctx_size,
             const uint8_t *pk, size_t pk_size, const char *ph, size_t ph_size) {
    return generic_verify("SLH-DSA-SHAKE-256f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size);
}

int CC_SLHDSA_sha2_128s_invariant_pure(void) { return 1; }
int CC_SLHDSA_sha2_192s_invariant_pure(void) { return 1; }
int CC_SLHDSA_sha2_256s_invariant_pure(void) { return 1; }
int CC_SLHDSA_sha2_128f_invariant_pure(void) { return 1; }
int CC_SLHDSA_sha2_192f_invariant_pure(void) { return 1; }
int CC_SLHDSA_sha2_256f_invariant_pure(void) { return 1; }
int CC_SLHDSA_shake_128s_invariant_pure(void) { return 1; }
int CC_SLHDSA_shake_192s_invariant_pure(void) { return 1; }
int CC_SLHDSA_shake_256s_invariant_pure(void) { return 1; }
int CC_SLHDSA_shake_128f_invariant_pure(void) { return 1; }
int CC_SLHDSA_shake_192f_invariant_pure(void) { return 1; }
int CC_SLHDSA_shake_256f_invariant_pure(void) { return 1; }


int generic_sign(char *alg, uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size, int det) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    OSSL_PARAM pkey_params[2], sig_params[3];
    size_t siglen = sig_size;

    sig_params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)ctx, ctx_size);
    sig_params[1] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    sig_params[2] = OSSL_PARAM_construct_end();

    pkey_params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void*)sk, sk_size);
    pkey_params[1] = OSSL_PARAM_construct_end();

    sctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (sctx == NULL)
        goto error;
    if (1 != EVP_PKEY_fromdata_init(sctx))
        goto error;
    if (EVP_PKEY_fromdata(sctx, &pkey, EVP_PKEY_PRIVATE_KEY, pkey_params) != 1)
        goto error;

    vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (vctx == NULL)
        goto error;
    sig_alg = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    if (sig_alg == NULL)
        goto error;
    if (1 != EVP_PKEY_sign_message_init(vctx, sig_alg, sig_params)) {
        fprintf(stderr, "sign_message_init failed\n");
        goto error;
    }
    if (1 != EVP_PKEY_sign(vctx, sig, &siglen, msg, msg_size)) {
        fprintf(stderr, "sign failed\n");
        goto error;
    }

    if (siglen != sig_size) return -1;

    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return 1;
error:
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    ERR_print_errors_fp(stderr);
    return 0;
}

int generic_verify(char *alg, const uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    OSSL_PARAM pkey_params[2];

    OSSL_PARAM sig_params[2] = {
        OSSL_PARAM_octet_string("context-string", (void*)ctx, ctx_size),
        OSSL_PARAM_END,
    };

    pkey_params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pk, pk_size);
    pkey_params[1] = OSSL_PARAM_construct_end();

    sctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (sctx == NULL)
        goto error;
    if (1 != EVP_PKEY_fromdata_init(sctx))
        goto error;
    if (EVP_PKEY_fromdata(sctx, &pkey, EVP_PKEY_PUBLIC_KEY, pkey_params) != 1)
        goto error;

    vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (vctx == NULL)
        goto error;
    sig_alg = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    if (sig_alg == NULL)
        goto error;
    if (1 != EVP_PKEY_verify_message_init(vctx, sig_alg, sig_params))
        goto error;
    if (1 != EVP_PKEY_verify(vctx, sig, sig_size, msg, msg_size))
        goto error;

    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return 1;
error:
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    ERR_print_errors_fp(stderr);
    return 0;
}
