#ifndef _AES_H_
#define _AES_H_

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCKLEN 16 // Block length in bytes - AES uses 128 bit blocks.

struct AES_ctx {
  uint8_t round_key[240]; // Array for the expanded key. Expanding a 256-bit
                          // key requires an array of 240 bytes.

  uint8_t
      Iv[AES_BLOCKLEN]; // The IV is the same size as a block, except for CTR
                        // mode where it's 12 bytes long. As the low 4 bytes are
                        // ignored, we can still use a 16-byte array.

  uint8_t Nk; // The number of 32-bit words comprising the cipher key.
  uint8_t Nr; // The number of rounds, depends on key length.
};

/**
 * @brief Initializes the context, expands the cipher key.
 *
 * @param ctx the context containing the parameters, expanded key, and IV.
 * @param key the cipher key to use.
 * @param key_length the key's length in bytes.
 */
void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key,
                  const size_t key_length);

/**
 * @brief Initializes the context, expands the cipher key, sets the IV.
 *
 * @param ctx the context containing the parameters, expanded key, and IV.
 * @param key the cipher key to use.
 * @param key_length the key's length in bytes.
 * @param iv the 128-bit IV to use.
 */
void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key,
                     const uint8_t key_length, const uint8_t *iv);

/**
 * @brief Sets the context's IV.
 *
 * @param ctx the context to update.
 * @param iv the IV to use.
 */
void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);

/**
 * @brief Encrypts a buffer in ECB mode.
 *
 * @param ctx the AES context, see AES_init_ctx*.
 * @param buf the buffer containing the plaintext.
 * @param length the length of the buffer in bytes. It must be a multiple of 16
 * (the AES block size).
 */
void AES_ECB_encrypt_buffer(const struct AES_ctx *ctx, uint8_t *buffer,
                            size_t length);
/**
 * @brief Decrypts a buffer in ECB mode.
 *
 * @param ctx the AES context, see AES_init_ctx*.
 * @param buffer the buffer containing the ciphertext.
 * @param length the length of the buffer in bytes. It must be a multiple of 16
 * (the AES block size).
 */
void AES_ECB_decrypt_buffer(const struct AES_ctx *ctx, uint8_t *buffer,
                            size_t length);

/**
 * @brief Encrypts a buffer in CBC mode.
 *
 * @param ctx AES context, initialized with a random IV (see AES_init_ctx_iv).
 * @param buffer the buffer containing the plaintext.
 * @param length the length of the buffer in bytes. It must be a multiple of 16
 * (the AES block size).
 */
void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer,
                            size_t length);
/**
 * @brief Decrypts a buffer in CBC mode.
 *
 * @param ctx AES context, initialized with the IV used to encrypt the plaintext
 * (see AES_init_ctx_iv).
 * @param buffer the buffer containing the ciphertext.
 * @param length the length of the buffer in bytes. It must be a multiple of 16
 * (the AES block size).
 */
void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer,
                            size_t length);

/**
 * @brief Encrypts or decrypts a buffer in CTR mode.
 *
 * @param ctx the AES context. When encrypting, initialize it with a random
 * 12-byte nonce. When decrypting, use the same nonce as the encryption. Do not
 * re-use nonces.
 * @param buffer the buffer containing the plaintext/ciphertext.
 * @param length the length of the buffer in bytes..
 */
void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer, size_t length);

/**
 * @brief Encrypts a buffer in CFB-{8,128} mode.
 *
 * @param ctx the AES context, initialized with a random IV.
 * @param buffer the buffer containing the plaintext.
 * @param length the length of the buffer in bytes.
 * @param segment_size the bit-width of a CFB segment, either 8 or 128.
 */
void AES_CFB_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer, size_t length,
                            size_t segment_size);

/**
 * @brief Decrypts a buffer in CFB-{8,128} mode.
 *
 * @param ctx the AES context, initialized with the IV used to encrypt the data.
 * @param buffer the buffer containing the ciphertext.
 * @param length the length of the buffer in bytes.
 * @param segment_size the bit-width of a CFB segment, either 8 or 128.
 */
void AES_CFB_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer, size_t length,
                            size_t segment_size);
#endif // _AES_H_
