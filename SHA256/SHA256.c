#include "SHA256.h"

uint32_t K[] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint32_t h0 = 0x6a09e667;
uint32_t h1 = 0xbb67ae85;
uint32_t h2 = 0x3c6ef372;
uint32_t h3 = 0xa54ff53a;
uint32_t h4 = 0x510e527f;
uint32_t h5 = 0x9b05688c;
uint32_t h6 = 0x1f83d9ab;
uint32_t h7 = 0x5be0cd19;

void print_bits(uint8_t *data, size_t length)
{
    for(size_t i = 0; i < length; i++)
    {
        fprintf(stdout, "%x ", data[i]);
    }
    fprintf(stdout, "\n");
}

uint32_t to_little_endian(uint32_t data)
{
   return ((data >> 24) & 0x000000FF) | ((data >>  8) & 0x0000FF00) | ((data <<  8) & 0x00FF0000) | ((data << 24) & 0xFF000000);
}

void print_bits32(uint32_t *data, size_t length)
{
    for(size_t i = 0; i < length; i++)
    {
        fprintf(stdout, "%x ", data[i]);
    }
    fprintf(stdout, "\n");
}


void SHA256_print_digest(uint32_t *digest)
{
    uint8_t *output = (uint8_t *)digest;
    for (size_t i = 0; i < 32; i++)
    {
        fprintf(stdout, "%02x", output[i]);
    }
    fprintf(stdout, "\n");
}

uint32_t right_rotate(uint32_t x, uint32_t c)
{
    return (x >> c) | (x << (32 - c));
}

uint8_t *SHA256_pad_message(uint8_t *message, size_t length)
{
    /* Formula to calculate padded size after adding single byte with 1 bit set. */
    size_t paddedLength = (64 - ((length + 9) % 64)) + length + 9;
    uint8_t *paddedMessage = calloc(paddedLength, sizeof(uint8_t));
    for (size_t i = 0; i < length; i++)
    {
        paddedMessage[i] = message[i];
    }

    /* Add a single 1 bit */
    paddedMessage[length] = 128;

    for (size_t i = 0; i < 8; i++)
    {
        paddedMessage[paddedLength - 1 - i] = ((length * 8) >> (i * 8)) & 0xFF;
    }
    length = paddedLength;
    return paddedMessage;
}

uint32_t *SHA256_rounds(uint8_t *paddedMessage, size_t paddedLength)
{
    for (int i = 0; i < paddedLength; i += 64)
    {
        uint32_t w[64];

        for (int j = 0; j < 16; j++)
        {
            w[j] = (paddedMessage[i + (j * 4)] << 24) | (paddedMessage[i + (j * 4) + 1] << 16) | (paddedMessage[i + (j * 4) + 2] << 8) | (paddedMessage[i + (j * 4) + 3]);
        }

        for (int j = 16; j < 64; j++)
        {
            uint32_t s0 = right_rotate(w[j - 15], 7) ^ right_rotate(w[j - 15], 18) ^ ((w[j - 15]) >> 3);
            uint32_t s1 = right_rotate(w[j - 2], 17) ^ right_rotate(w[j - 2], 19) ^ ((w[j - 2]) >> 10);
            w[j] = w[j - 16] + s0 + w[j - 7] + s1;
        }

        /* Initialize eight working variables */
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (int j = 0; j < 64; j++)
        {
            uint32_t S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + K[j] + w[j];
            uint32_t S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    
    uint32_t *digest = malloc(sizeof(uint32_t) * 8);
    digest[0] = to_little_endian(h0);
    digest[1] = to_little_endian(h1);
    digest[2] = to_little_endian(h2);
    digest[3] = to_little_endian(h3);
    digest[4] = to_little_endian(h4);
    digest[5] = to_little_endian(h5);
    digest[6] = to_little_endian(h6);
    digest[7] = to_little_endian(h7);
    return digest;
}

uint32_t *SHA256_compute_digest(uint8_t *message, size_t messageLength)
{
    size_t paddedLength = (64 - ((messageLength + 9) % 64)) + messageLength + 9;
    uint8_t *paddedMessage = SHA256_pad_message(message, messageLength);
    print_bits(paddedMessage, paddedLength);
    uint32_t *digest = SHA256_rounds(paddedMessage, paddedLength);
    free(paddedMessage);
    return digest;
}