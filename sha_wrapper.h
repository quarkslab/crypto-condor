#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Converts a hexadecimal string to an array of bytes.
 *
 * @param src The hexadecimal string to convert.
 * @param dst An array of bytes to fill. Must be allocated.
 * @param len The size of src and dst in bytes.
 */
static void hex_to_int(const char *src, unsigned char *dst, size_t len) {
  for (size_t i = 0; i < len; i++) {
    dst[i] = (src[2 * i] % 32 + 9) % 25 * 16 + (src[2 * i + 1] % 32 + 9) % 25;
  }
}

/**
 * @brief Prints an array of bytes in hexadecimal.
 *
 * @param src array of bytes.
 * @param length of the array.
 */
static void print_hex(const unsigned char *src, size_t length) {
  for (size_t i = 0; i < length; i++)
    printf("%02hhx", src[i]);
  printf("\n");
}

/**
 * @brief Parses the command-line arguments given.
 *
 * Command-line arguments are given through argc/argv and parsed with getopt.
 * The parsed arguments are stored in the rest of this function's arguments.
 *
 * @param[in] argc main's argc.
 * @param[in] argv main's argv.
 * @param[out] input The array where to store the input message. This function
 * allocates input_len bytes.
 * @param[out] input_len The length of the parsed input.
 * @param[out] digest The array where to store the resulting digest. This
 * function allocates digest_len bytes.
 * @param[out] digest_len The size of the digest.
 */
static void parse(int argc, char **argv, uint8_t **input, size_t *input_len,
                  uint8_t **digest, size_t *digest_len) {
  int c;

  while (1) {
    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"digest-length", required_argument, 0, 'l'},
        {0, 0, 0, 0}};

    int option_index = 0;

    c = getopt_long(argc, argv, "l:i:", long_options, &option_index);

    if (c == -1)
      break;

    switch (c) {

    case 'l':
      (*digest_len) = atol(optarg);
      (*digest) = (uint8_t *)malloc((*digest_len) * sizeof(uint8_t));
      break;

    case 'i':
      (*input_len) = strlen(optarg) / 2;
      (*input) = (uint8_t *)malloc((*input_len) * sizeof(uint8_t));
      hex_to_int(optarg, (*input), (*input_len));
      break;

    default:
      break;
    }
  }
}