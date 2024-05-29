#include "sha_wrapper.h"
/**
 * TODO: Add your headers here.
 */

int main(int argc, char **argv) {

  uint8_t *input, *digest;
  size_t input_len = 0, digest_len = 0;

  parse(argc, argv, &input, &input_len, &digest, &digest_len);

  /**
   * TODO: call your implementation here.
   * The available arguments are:
   *
   * @param input is the message to hash.
   * @param input_len is its length in bytes.
   * @param digest is a malloc'd array of size digest_len to store the resulting
   *digest.
   * @param digest_len is the length of the digest according to the chosen
   *algorithm.
   */

  // Print the resulting digest at the end. This should be the only output.
  print_hex(digest, digest_len);

  free(input);
  free(digest);

  return 0;
}
