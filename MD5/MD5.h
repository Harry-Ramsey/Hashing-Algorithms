#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

uint32_t *MD5_compute_digest(uint8_t *message, size_t messageLength);
void MD5_print_digest(uint32_t *digest);