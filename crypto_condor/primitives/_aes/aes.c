#include "aes.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // CBC mode, for memset

// Number of bytes per row of the state, equals to block length divided by 32.
#define Nb 4

typedef uint8_t state_t[4][4];

static const uint8_t SBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static const uint8_t RSBox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

static const uint8_t Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
                                 0x20, 0x40, 0x80, 0x1b, 0x36};

static void KeyExpansion(struct AES_ctx *ctx, const uint8_t *key) {
  uint32_t i, j, k;
  uint8_t temp[4];

  uint8_t *round_key = ctx->round_key;
  uint8_t Nk = ctx->Nk, Nr = ctx->Nr;

  for (i = 0; i < Nk; ++i) {
    round_key[(i * 4) + 0] = key[(i * 4) + 0];
    round_key[(i * 4) + 1] = key[(i * 4) + 1];
    round_key[(i * 4) + 2] = key[(i * 4) + 2];
    round_key[(i * 4) + 3] = key[(i * 4) + 3];
  }

  for (i = Nk; i < Nb * (Nr + 1); ++i) {
    {
      k = (i - 1) * 4;
      temp[0] = round_key[k + 0];
      temp[1] = round_key[k + 1];
      temp[2] = round_key[k + 2];
      temp[3] = round_key[k + 3];
    }

    if (i % Nk == 0) {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        temp[0] = SBox[temp[0]];
        temp[1] = SBox[temp[1]];
        temp[2] = SBox[temp[2]];
        temp[3] = SBox[temp[3]];
      }

      temp[0] = temp[0] ^ Rcon[i / Nk];
    }
    if ((Nk == 8) && (i % Nk == 4)) {
      // Function Subword()
      {
        temp[0] = SBox[temp[0]];
        temp[1] = SBox[temp[1]];
        temp[2] = SBox[temp[2]];
        temp[3] = SBox[temp[3]];
      }
    }
    j = i * 4;
    k = (i - Nk) * 4;
    round_key[j + 0] = round_key[k + 0] ^ temp[0];
    round_key[j + 1] = round_key[k + 1] ^ temp[1];
    round_key[j + 2] = round_key[k + 2] ^ temp[2];
    round_key[j + 3] = round_key[k + 3] ^ temp[3];
  }
}

// Multiply two bytes in the AES Galois field.
static uint8_t GMul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  while (a != 0 && b != 0) {
    if (b & 1) {
      p ^= a;
    }
    if (a & 0x80) {
      a = (a << 1) ^ 0x11b;
    } else {
      a <<= 1;
    }
    b >>= 1;
  }
  return p;
}

static void AddRoundKey(state_t *state, const uint8_t *round_key,
                        uint8_t round) {
  uint8_t i, j;
  uint8_t offset = round * Nb * 4;
  for (i = 0; i < 4; i++)
    for (j = 0; j < 4; j++)
      (*state)[i][j] ^= round_key[offset + (i * Nb) + j];
}

static void SubBytes(state_t *state) {
  uint8_t i, j;
  for (i = 0; i < 4; i++)
    for (j = 0; j < 4; j++)
      (*state)[i][j] = SBox[(*state)[i][j]];
}

static void ShiftRows(state_t *state) {
  uint8_t temp;

  // Row 0 stays in place.

  // Row 1
  temp = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Row 2
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;
  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Row 3
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static void MixColumns(state_t *state) {
  uint8_t c0, c1, c2, c3, i;
  for (i = 0; i < 4; i++) {
    c0 = (*state)[i][0];
    c1 = (*state)[i][1];
    c2 = (*state)[i][2];
    c3 = (*state)[i][3];
    (*state)[i][0] =
        GMul(c0, 0x02) ^ GMul(c1, 0x03) ^ GMul(c2, 0x01) ^ GMul(c3, 0x01);
    (*state)[i][1] =
        GMul(c0, 0x01) ^ GMul(c1, 0x02) ^ GMul(c2, 0x03) ^ GMul(c3, 0x01);
    (*state)[i][2] =
        GMul(c0, 0x01) ^ GMul(c1, 0x01) ^ GMul(c2, 0x02) ^ GMul(c3, 0x03);
    (*state)[i][3] =
        GMul(c0, 0x03) ^ GMul(c1, 0x01) ^ GMul(c2, 0x01) ^ GMul(c3, 0x02);
  }
}

static void InvMixColumns(state_t *state) {
  int i;
  uint8_t c0, c1, c2, c3;
  for (i = 0; i < 4; ++i) {
    c0 = (*state)[i][0];
    c1 = (*state)[i][1];
    c2 = (*state)[i][2];
    c3 = (*state)[i][3];

    (*state)[i][0] =
        GMul(c0, 0x0e) ^ GMul(c1, 0x0b) ^ GMul(c2, 0x0d) ^ GMul(c3, 0x09);
    (*state)[i][1] =
        GMul(c0, 0x09) ^ GMul(c1, 0x0e) ^ GMul(c2, 0x0b) ^ GMul(c3, 0x0d);
    (*state)[i][2] =
        GMul(c0, 0x0d) ^ GMul(c1, 0x09) ^ GMul(c2, 0x0e) ^ GMul(c3, 0x0b);
    (*state)[i][3] =
        GMul(c0, 0x0b) ^ GMul(c1, 0x0d) ^ GMul(c2, 0x09) ^ GMul(c3, 0x0e);
  }
}

static void InvSubBytes(state_t *state) {
  uint8_t i, j;
  for (i = 0; i < 4; i++)
    for (j = 0; j < 4; j++)
      (*state)[i][j] = RSBox[(*state)[i][j]];
}

static void InvShiftRows(state_t *state) {
  uint8_t temp;

  // Row 0 stays in place.

  // Row 1
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Row 2
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;
  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Row 3
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}

static void Cipher(state_t *state, const struct AES_ctx *ctx) {

  const uint8_t *round_key = ctx->round_key;
  const uint8_t Nr = ctx->Nr;

  AddRoundKey(state, round_key, 0);

  for (uint8_t round = 1; round < Nr; ++round) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, round_key, round);
  }

  // Last round skips MixColumns.
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, round_key, Nr);
}

static void InvCipher(state_t *state, const struct AES_ctx *ctx) {

  const uint8_t *round_key = ctx->round_key;
  const uint8_t Nr = ctx->Nr;

  AddRoundKey(state, round_key, Nr);

  for (uint8_t round = (Nr - 1); round > 0; round--) {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, round_key, round);
    InvMixColumns(state);
  }

  // Last round skips InvMixColumns.
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(state, round_key, 0);
}

static void XorBlock(uint8_t *dst, const uint8_t *src) {
  for (uint8_t i = 0; i < AES_BLOCKLEN; ++i)
    dst[i] ^= src[i];
}

/*****************************************************************************/
/* Init                                                                      */
/*****************************************************************************/

void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key,
                  const size_t key_length) {

  switch (key_length) {
  case 16:
    ctx->Nk = 4;
    ctx->Nr = 10;
    break;
  case 24:
    ctx->Nk = 6;
    ctx->Nr = 12;
    break;
  case 32:
    ctx->Nk = 8;
    ctx->Nr = 14;
    break;
  default:
    printf("Wrong key length %ld!\n", key_length);
    exit(EXIT_FAILURE);
  }

  KeyExpansion(ctx, key);
}

void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key,
                     const uint8_t key_length, const uint8_t *iv) {
  AES_init_ctx(ctx, key, key_length);
  memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv) {
  memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

/*****************************************************************************/
/* ECB                                                                       */
/*****************************************************************************/

void AES_ECB_encrypt_buffer(const struct AES_ctx *ctx, uint8_t *buffer,
                            size_t length) {
  for (size_t offset = 0; offset < length; offset += AES_BLOCKLEN)
    Cipher((state_t *)(buffer + offset), ctx);
}

void AES_ECB_decrypt_buffer(const struct AES_ctx *ctx, uint8_t *buffer,
                            size_t length) {
  for (size_t offset = 0; offset < length; offset += AES_BLOCKLEN)
    InvCipher((state_t *)(buffer + offset), ctx);
}

/*****************************************************************************/
/* CBC                                                                       */
/*****************************************************************************/

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer,
                            size_t length) {
  size_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN) {
    XorBlock(buffer, Iv);
    Cipher((state_t *)buffer, ctx);
    Iv = buffer;
    buffer += AES_BLOCKLEN;
  }
  /* store Iv in ctx for next call */
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer,
                            size_t length) {
  size_t i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN) {
    memcpy(storeNextIv, buffer, AES_BLOCKLEN);
    InvCipher((state_t *)buffer, ctx);
    XorBlock(buffer, ctx->Iv);
    memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
    buffer += AES_BLOCKLEN;
  }
}

/*****************************************************************************/
/* CTR                                                                       */
/*****************************************************************************/

void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer,
                           size_t length) {

  size_t i;
  // Counter block: 12 bytes of nonce (ctx's IV) + 4 bytes of counter value.
  uint8_t counter[AES_BLOCKLEN], keystream[AES_BLOCKLEN];
  // Counter value starts at 1.
  uint32_t ct = 1u;

  memcpy(counter, ctx->Iv, 12);
  counter[12] = (ct >> 24);
  counter[13] = (ct >> 16) & 0xff;
  counter[14] = (ct >> 8) & 0xff;
  counter[15] = ct & 0xff;

  for (i = 0; i < length / AES_BLOCKLEN; i++) {
    // Update keystream.
    memcpy(keystream, counter, AES_BLOCKLEN);
    Cipher((state_t *)(keystream), ctx);

    // Xor with plaintext.
    XorBlock((buffer + i * AES_BLOCKLEN), keystream);

    // Update counter value.
    ++ct;
    // Exit if value is wrapping.
    if (ct == 0) {
      printf("Error: CTR counter wrapping around.\n");
      exit(EXIT_FAILURE);
    }
    counter[12] = (ct >> 24);
    counter[13] = (ct >> 16) & 0xff;
    counter[14] = (ct >> 8) & 0xff;
    counter[15] = ct & 0xff;
  }

  // Treat remaining bytes, if any.
  size_t full_blocks = (length / AES_BLOCKLEN) * AES_BLOCKLEN;
  if (length != full_blocks) {
    Cipher((state_t *)(counter), ctx);
    for (i = full_blocks; i < length; i++)
      buffer[i] ^= counter[i % AES_BLOCKLEN];
  }
}

/*****************************************************************************/
/* CFB                                                                       */
/*****************************************************************************/

static void AES_CFB8_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer,
                                    size_t length) {
  size_t i, j;
  uint8_t input[AES_BLOCKLEN], output[AES_BLOCKLEN];
  memcpy(input, ctx->Iv, AES_BLOCKLEN);

  for (i = 0; i < length; i++) {
    // Get output block by encrypting input block.
    memcpy(output, input, AES_BLOCKLEN);
    Cipher((state_t *)(output), ctx);

    // Encrypt 8 bits with 8 MSB of output block.
    buffer[i] ^= output[0];

    // Shift input block 8 bits to the left and add current ciphertext byte.
    for (j = 0; j < AES_BLOCKLEN - 1; j++)
      input[j] = input[j + 1];
    input[AES_BLOCKLEN - 1] = buffer[i];
  }
}

static void AES_CFB128_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer,
                                      size_t length) {
  size_t i;
  uint8_t keystream[AES_BLOCKLEN];
  memcpy(keystream, ctx->Iv, AES_BLOCKLEN);

  for (i = 0; i < length; i++) {
    // Update keystream.
    if (i % AES_BLOCKLEN == 0) {
      // Copy previous block to keystream if we have already encrypted at least
      // one block, otherwise the IV is used.
      if (i != 0) {
        memcpy(keystream, (buffer + i - AES_BLOCKLEN), AES_BLOCKLEN);
      }
      Cipher((state_t *)(keystream), ctx);
    }
    buffer[i] ^= keystream[i % AES_BLOCKLEN];
  }
}

void AES_CFB_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer, size_t length,
                            size_t segment_size) {
  if (segment_size == 8)
    AES_CFB8_encrypt_buffer(ctx, buffer, length);
  else if (segment_size == 128)
    AES_CFB128_encrypt_buffer(ctx, buffer, length);
  else {
    printf("Error: segment_size must be 8 or 128 bits.\n");
    exit(EXIT_FAILURE);
  }
}

static void AES_CFB8_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer,
                                    size_t length) {
  size_t i, j;
  uint8_t input[AES_BLOCKLEN], output[AES_BLOCKLEN], ct;
  memcpy(input, ctx->Iv, AES_BLOCKLEN);

  for (i = 0; i < length; i++) {
    // Get output block by encrypting input block.
    memcpy(output, input, AES_BLOCKLEN);
    Cipher((state_t *)(output), ctx);

    // Save the current ciphertext byte for the next input block.
    ct = buffer[i];

    // Encrypt 8 bits with 8 MSB of output block.
    buffer[i] ^= output[0];

    // Shift input block 8 bits to the left and add previous ciphertext byte.
    for (j = 0; j < AES_BLOCKLEN - 1; j++)
      input[j] = input[j + 1];
    input[AES_BLOCKLEN - 1] = ct;
  }
}

static void AES_CFB128_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer,
                                      size_t length) {
  size_t i;
  uint8_t keystream[AES_BLOCKLEN], ct[AES_BLOCKLEN];
  memcpy(keystream, ctx->Iv, AES_BLOCKLEN);

  for (i = 0; i < length; i++) {
    // Update keystream.
    if (i % AES_BLOCKLEN == 0) {
      // Copy previous block to keystream if we have already decrypted at least
      // one block, otherwise the IV is used.
      if (i != 0) {
        memcpy(keystream, ct, AES_BLOCKLEN);
      }
      Cipher((state_t *)(keystream), ctx);
      // Save the current ciphertext block for the next keystream.
      memcpy(ct, (buffer + i), AES_BLOCKLEN);
    }
    buffer[i] ^= keystream[i % AES_BLOCKLEN];
  }
}

void AES_CFB_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer, size_t length,
                            size_t segment_size) {
  if (segment_size == 8)
    AES_CFB8_decrypt_buffer(ctx, buffer, length);
  else if (segment_size == 128)
    AES_CFB128_decrypt_buffer(ctx, buffer, length);
  else {
    printf("Error: segment_size must be 8 or 128 bits.\n");
    exit(EXIT_FAILURE);
  }
}
