#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/core_names.h"
#include <string.h>

int generic_sign_prehash(char *alg, uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size,
            int det);

int generic_verify_prehash(char *alg, const uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size);

int CC_SLHDSA_sha2_128s_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHA2-128s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_sha2_192s_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHA2-192s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_sha2_256s_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHA2-256s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_sha2_128f_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHA2-128f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_sha2_192f_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHA2-192f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_sha2_256f_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHA2-256f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_shake_128s_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHAKE-128s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_shake_192s_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHAKE-192s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_shake_256s_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHAKE-256s", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_shake_128f_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHAKE-128f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_shake_192f_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHAKE-192f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_shake_256f_sign_prehash_det(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size) {
    return generic_sign_prehash("SLH-DSA-SHAKE-256f", sig, sig_size, msg, msg_size, ctx, ctx_size, sk, sk_size, ph, ph_size, 1);
}

int CC_SLHDSA_sha2_128s_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHA2-128s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_sha2_192s_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHA2-192s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_sha2_256s_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHA2-256s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_sha2_128f_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHA2-128f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_sha2_192f_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHA2-192f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_sha2_256f_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHA2-256f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_shake_128s_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHAKE-128s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_shake_192s_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHAKE-192s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_shake_256s_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHAKE-256s", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_shake_128f_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHAKE-128f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_shake_192f_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHAKE-192f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_shake_256f_verify_prehash(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    return generic_verify_prehash("SLH-DSA-SHAKE-256f", sig, sig_size, msg, msg_size, ctx, ctx_size, pk, pk_size, ph, ph_size);
}

int CC_SLHDSA_sha2_128s_invariant_prehash(void) { return 1; }
int CC_SLHDSA_sha2_192s_invariant_prehash(void) { return 1; }
int CC_SLHDSA_sha2_256s_invariant_prehash(void) { return 1; }
int CC_SLHDSA_sha2_128f_invariant_prehash(void) { return 1; }
int CC_SLHDSA_sha2_192f_invariant_prehash(void) { return 1; }
int CC_SLHDSA_sha2_256f_invariant_prehash(void) { return 1; }
int CC_SLHDSA_shake_128s_invariant_prehash(void) { return 1; }
int CC_SLHDSA_shake_192s_invariant_prehash(void) { return 1; }
int CC_SLHDSA_shake_256s_invariant_prehash(void) { return 1; }
int CC_SLHDSA_shake_128f_invariant_prehash(void) { return 1; }
int CC_SLHDSA_shake_192f_invariant_prehash(void) { return 1; }
int CC_SLHDSA_shake_256f_invariant_prehash(void) { return 1; }

static int md_to_oid(unsigned char *oid, EVP_MD *md) {
	int nid = EVP_MD_get_type(md);
    if (nid == NID_undef) return 0;
	ASN1_OBJECT *obj = OBJ_nid2obj(nid);
    if (obj == NULL) return 0;
	size_t objlen = OBJ_length(obj);
	const unsigned char *data = OBJ_get0_data(obj);
    oid[0] = 0x06;
    oid[1] = 0x09;
    for (size_t i = 0; i < objlen; i++)
        oid[2 + i] = data[i];
    return 1;
}

static int encode_message(uint8_t **encoded_msg, size_t *encoded_len, const char *ph, const uint8_t *msg, size_t msg_size, const uint8_t *ctx, size_t ctx_size) {
    EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;
    uint8_t *dgst = NULL, *emsg = NULL, *oid = NULL;
    size_t elen = 0;
    unsigned int dlen = 0;
    int ret = 0;

    md = EVP_MD_fetch(NULL, ph, NULL);
    if (md == NULL)
        goto end;
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        goto end;

    if (0 == strncmp(ph, "SHAKE-128", 9)) {
        dlen = 32;
        if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
            goto end;
        if (1 != EVP_DigestUpdate(mdctx, msg, msg_size))
            goto end;
        dgst = (unsigned char *)OPENSSL_malloc(dlen);
        if (dgst == NULL)
            goto end;
        if (1 != EVP_DigestFinalXOF(mdctx, dgst, dlen))
            goto end;
    } else if (0 == strncmp(ph, "SHAKE-256", 9)) {
        dlen = 64;
        if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
            goto end;
        if (1 != EVP_DigestUpdate(mdctx, msg, msg_size))
            goto end;
        dgst = (unsigned char *)OPENSSL_malloc(dlen);
        if (dgst == NULL)
            goto end;
        if (1 != EVP_DigestFinalXOF(mdctx, dgst, dlen))
            goto end;
    } else {
        dlen = EVP_MD_get_size(md);
        if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
            goto end;
        if (1 != EVP_DigestUpdate(mdctx, msg, msg_size))
            goto end;
        dgst = (unsigned char *)OPENSSL_malloc(dlen);
        if (dgst == NULL)
            goto end;
        if (1 != EVP_DigestFinal_ex(mdctx, dgst, &dlen))
            goto end;
    }
    //
    // Create the encoded message
    emsg = (uint8_t *)OPENSSL_malloc(1+1+ctx_size+11+dlen);
    if (emsg == NULL)
        goto end;
    oid = (unsigned char *)OPENSSL_malloc(11);
    if (oid == NULL)
        goto end;
    if (1 != md_to_oid(oid, md))
        goto end;
    emsg[0] = 1; elen++;
    emsg[1] = (uint8_t)ctx_size; elen++;
    memcpy(emsg + elen, ctx, ctx_size);
    elen += ctx_size;
    memcpy(emsg + elen, oid, 11);
    elen += 11;
    memcpy(emsg + elen, dgst, dlen);
    elen += dlen;

    (*encoded_msg) = emsg;
    (*encoded_len) = elen;
    ret = 1;

end:
    EVP_MD_free(md);
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(oid);
    OPENSSL_free(dgst);
    return ret;

}

int generic_sign_prehash(char *alg, uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size,
            int det) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    OSSL_PARAM pkey_params[2], sig_params[4];
    uint8_t *encoded_msg = NULL;
    size_t siglen = sig_size, encoded_len = 0;
    int encoding = 0;

    sig_params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)ctx, ctx_size);
    sig_params[1] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    sig_params[2] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encoding);
    sig_params[3] = OSSL_PARAM_construct_end();

    pkey_params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void*)sk, sk_size);
    pkey_params[1] = OSSL_PARAM_construct_end();

    sctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (sctx == NULL)
        goto error;
    if (1 != EVP_PKEY_fromdata_init(sctx))
        goto error;
    if (EVP_PKEY_fromdata(sctx, &pkey, EVP_PKEY_PRIVATE_KEY, pkey_params) != 1)
        goto error;

    if (1 != encode_message(&encoded_msg, &encoded_len, ph, msg, msg_size, ctx, ctx_size)) {
        fprintf(stderr, "encoding message failed\n");
        goto error;
    }

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
    if (1 != EVP_PKEY_sign(vctx, sig, &siglen, encoded_msg, encoded_len)) {
        fprintf(stderr, "sign failed\n");
        goto error;
    }

    if (siglen != sig_size) return -1;

    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    OPENSSL_free(encoded_msg);
    return 1;
error:
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    OPENSSL_free(encoded_msg);
    ERR_print_errors_fp(stderr);
    return 0;
}

int generic_verify_prehash(char *alg, const uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    OSSL_PARAM pkey_params[2], sig_params[3];
    uint8_t *encoded_msg = NULL;
    size_t encoded_len = 0;
    int encoding = 0;

    sig_params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)ctx, ctx_size);
    sig_params[1] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encoding);
    sig_params[2] = OSSL_PARAM_construct_end();

    pkey_params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pk, pk_size);
    pkey_params[1] = OSSL_PARAM_construct_end();

    sctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (sctx == NULL)
        goto error;
    if (1 != EVP_PKEY_fromdata_init(sctx))
        goto error;
    if (EVP_PKEY_fromdata(sctx, &pkey, EVP_PKEY_PUBLIC_KEY, pkey_params) != 1)
        goto error;

    if (1 != encode_message(&encoded_msg, &encoded_len, ph, msg, msg_size, ctx, ctx_size)) {
        fprintf(stderr, "encoding message failed\n");
        goto error;
    }

    vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (vctx == NULL)
        goto error;
    sig_alg = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    if (sig_alg == NULL)
        goto error;
    if (1 != EVP_PKEY_verify_message_init(vctx, sig_alg, sig_params))
        goto error;
    if (1 != EVP_PKEY_verify(vctx, sig, sig_size, encoded_msg, encoded_len))
        goto error;

    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    OPENSSL_free(encoded_msg);
    return 1;
error:
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    OPENSSL_free(encoded_msg);
    ERR_print_errors_fp(stderr);
    return 0;
}
