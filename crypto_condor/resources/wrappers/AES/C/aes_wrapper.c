#include "aes_wrapper.h"
/**
 * TODO: Add your headers here.
 */

int main(int argc, char **argv) {

  int mode = -1, encrypt = 1, tag_ok = 0;

  uint8_t *key = NULL;
  size_t key_len = 0;
  // Input and output should have the same length (input_len) except for modes
  // that involve padding such as CBC-PKCS7.
  uint8_t *input = NULL, *output = NULL;
  size_t input_len = 0, output_len = 0;
  // The IV or nonce depending on the mode of operation.
  uint8_t *iv = NULL;
  size_t iv_len = 0;
  size_t segment_size = 0;
  uint8_t *aad = NULL, *tag = NULL;
  size_t aad_len = 0, tag_len = 0;

  parse(argc, argv, &mode, &key, &key_len, &input, &input_len, &iv, &iv_len,
        &segment_size, &encrypt, &aad, &aad_len, &tag, &tag_len);

  /**
   * TO FILL: Call your implementation here. Refer to the documentation for
   * examples. Available arguments are:
   *
   * @param encrypt Whether to encrypt or decrypt the input message.
   * @param key The symmetric key.
   * @param key_len The length of the key, either 128, 192, or 256.
   * @param input The input message.
   * @param input_len The size of the input message in bytes, deduced from the
   * --text argument.
   * @param output An array to store the output message.
   * @param iv The IV or nonce.
   * @param iv_len The length of the IV/nonce in bytes, deduced from the --iv
   * argument.
   * @param segment_size (CFB modes) The size of the segmentation in bits.
   * @param aad (AEAD modes) The optional associated data.
   * @param aad_len (AEAD modes) The length of the aad in bytes, deduced from
   * the --aad argument.
   * @param tag (AEAD modes) The tag for authenticated modes.
   * @param tag_len (AEAD modes) The length of the tag in bytes, either deduced
   * from the --tag argument when decrypting or specified with the --tag-length
   * argument when encrypting.
   */

  /**
   * The results of each operation are printed in a certain format depending on
   * the mode of operation: classic modes should only output the
   * ciphertext/plaintext in hexadecimal while AEAD modes should output either
   * the ciphertext and tag when encrypting or the result of the tag
   * verification and the plaintext if the verification succeeded.
   */
  if (encrypt) {
    /**
     * TODO: Call the encryption function here. Don't forget to verify
     * output_len is the correct size; you may need to increase it if there is
     * padding.
     */
    output_len = input_len;
    output = malloc(output_len * sizeof(uint8_t));

    /**
     * Then print the results of the operation.
     */
    if (mode == AEAD_MODE) {
      printf("msg = ");
      print_hex(output, output_len);
      printf("tag = ");
      print_hex(tag, tag_len);
    } else {
      print_hex(output, output_len);
    }
  } else {
    /**
     * TODO: Call the decryption function here. Don't forget to verify
     * output_len is the correct size; you may need to increase it if there is
     * padding.
     */
    output_len = input_len;
    output = malloc(output_len * sizeof(uint8_t));

    /**
     * Then print the results of the operation. Set tag_ok to 1 if the mode
     * of operation tested is authenticated (e.g. GCM) and the verification of
     * the tag was successful.
     */
    if (mode == AEAD_MODE) {
      if (tag_ok) {
        printf("tag = OK\n");
        printf("msg = ");
        print_hex(output, output_len);
      } else {
        printf("tag = FAIL\n");
        printf("msg = \n");
      }
    } else {
      print_hex(output, output_len);
    }
  }

  // Free malloc'd memory.
  free(key);
  free(input);
  free(output);
  if (iv_len > 0)
    free(iv);
  if (aad_len > 0)
    free(aad);
  if (tag_len > 0)
    free(tag);
  return 0;
}
