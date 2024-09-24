#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AEAD_MODE 1

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
 * @param len of the array.
 */
static void print_hex(const unsigned char *src, size_t len) {
  for (size_t i = 0; i < len; i++)
    printf("%02hhx", src[i]);
  printf("\n");
}

static void parse(int argc, char **argv, int *mode, uint8_t **key,
                  size_t *key_len, uint8_t **input, size_t *input_len,
                  uint8_t **iv, size_t *iv_len, size_t *segment_size,
                  int *encrypt, uint8_t **aad, size_t *aad_len, uint8_t **tag,
                  size_t *tag_len) {
  int c;

  while (1) {
    static struct option long_options[] = {
        {"iv", required_argument, 0, 'i'},
        {"key", required_argument, 0, 'k'},
        {"mode", required_argument, 0, 'm'},
        {"text", required_argument, 0, 't'},
        {"decrypt", no_argument, 0, 'd'},
        {"segment-size", required_argument, 0, 's'},
        {"aad", required_argument, 0, 'a'},
        {"tag", required_argument, 0, 'g'},
        {"tag-length", required_argument, 0, 'l'},
        {0, 0, 0, 0}};

    int option_index = 0;

    c = getopt_long(argc, argv, "a:dg:i:k:l:m:s:t:", long_options,
                    &option_index);

    if (c == -1)
      break;

    switch (c) {

    case 'd':
      (*encrypt) = 0;
      break;

    case 'i':
      (*iv_len) = strlen(optarg) / 2;
      (*iv) = (uint8_t *)malloc((*iv_len) * sizeof(uint8_t));
      hex_to_int(optarg, (*iv), (*iv_len));
      break;

    case 'k':
      (*key_len) = strlen(optarg) / 2;
      (*key) = (uint8_t *)malloc((*key_len) * sizeof(uint8_t));
      hex_to_int(optarg, (*key), (*key_len));
      break;

    case 'm':
      (*mode) = atoi(optarg);
      break;

    case 's':
      (*segment_size) = atoi(optarg);
      break;

    case 't':
      (*input_len) = strlen(optarg) / 2;
      (*input) = (uint8_t *)malloc((*input_len) * sizeof(uint8_t));
      hex_to_int(optarg, (*input), (*input_len));
      break;

    case 'a':
      (*aad_len) = strlen(optarg) / 2;
      (*aad) = (uint8_t *)malloc((*aad_len) * sizeof(uint8_t));
      hex_to_int(optarg, (*aad), (*aad_len));
      break;

    case 'g':
      (*tag_len) = strlen(optarg) / 2;
      (*tag) = (uint8_t *)malloc((*tag_len) * sizeof(uint8_t));
      hex_to_int(optarg, (*tag), (*tag_len));
      break;

    case 'l':
      (*tag_len) = atol(optarg);
      (*tag) = (uint8_t *)malloc((*tag_len) * sizeof(uint8_t));
      break;

    default:
      break;
    }
  }
}
