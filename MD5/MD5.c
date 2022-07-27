#include "MD5.h"

uint32_t s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

uint32_t K[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

uint32_t a0 = 0x67452301;
uint32_t b0 = 0xefcdab89;
uint32_t c0 = 0x98badcfe;
uint32_t d0 = 0x10325476;

uint32_t left_rotate(uint32_t x, uint32_t c)
{
    return (x << c) | (x >> (32 - c));
}

void MD5_print_digest(uint32_t *digest)
{
    uint8_t *output = (uint8_t *)digest;
    for (size_t i = 0; i < 16; i++)
    {
        fprintf(stdout, "%02x", output[i]);
    }
}

uint8_t *MD5_pad_message(uint8_t *message, size_t length)
{
    size_t paddedLength = (64 - ((length + 9) % 64)) + length + 9;
    uint8_t *paddedMessage = calloc(paddedLength, sizeof(uint8_t));
    for (size_t i = 0; i < length; i++)
    {
        paddedMessage[i] = message[i];
    }

    paddedMessage[length] = 128;

    for (size_t i = 0; i < 8; i++)
    {
        paddedMessage[paddedLength - 8 + i] = ((length * 8) >> (i * 8)) & 0xFF;
    }
    length = paddedLength;
    return paddedMessage;
}

uint32_t *MD5_rounds(uint8_t *paddedMessage, size_t paddedLength)
{
    /* Process message in 512-bit chunks. */
    for (size_t i = 0; i < paddedLength; i += 64)
    {
        uint32_t *w = (uint32_t *)(paddedMessage + i);

        /* Initalise hash value for this chunk. */
        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (size_t j = 0; j < 64; j++)
        {
            uint32_t F, g, dTemp;
            switch (j / 16)
            {
            case 0:
                F = (B & C) | ((~B) & D);
                g = j;
                break;
            case 1:
                F = (D & B) | ((~D) & C);
                g = (5 * j + 1) % 16;
                break;
            case 2:
                F = B ^ C ^ D;
                g = (3 * j + 5) % 16;
                break;
            case 3:
                F = C ^ (B | (~D));
                g = (7 * j) % 16;
                break;
            }
            dTemp = D;
            D = C;
            C = B;
            B = B + left_rotate((F + A + K[j] + w[g]), s[j]);
            A = dTemp;
        }
        a0 += A;
        b0 += B;
        c0 += C;
        d0 += D;
    }
    uint32_t *digest = malloc(sizeof(uint32_t) * 4);
    digest[0] = a0;
    digest[1] = b0;
    digest[2] = c0;
    digest[3] = d0;
    return digest;
}

uint32_t *MD5_compute_digest(uint8_t *message, size_t messageLength)
{
    size_t paddedLength = (64 - ((messageLength + 9) % 64)) + messageLength + 9;
    uint8_t *paddedMessage = MD5_pad_message(message, messageLength);
    uint32_t *digest = MD5_rounds(paddedMessage, paddedLength);
    free(paddedMessage);
    return digest;
}