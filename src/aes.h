#ifndef AES_H
#define AES_H

#include <stdint.h>

/* Menetapkan ukuran blok dan kunci AES-128 sebesar 16 byte. */
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16

/* Menyimpan 11 kunci ronde yang dipakai untuk enkripsi dan dekripsi AES-128. */
typedef struct {
    uint8_t round_keys[176];
} AES128Context;

/* Mengisi konteks dengan kunci ronde hasil ekspansi kunci utama. */
void aes128_init(AES128Context *ctx, const uint8_t key[AES_KEY_SIZE]);
/* Mengenkripsi satu blok 16 byte menggunakan kunci pada konteks. */
void aes128_encrypt_block(const AES128Context *ctx,
                          const uint8_t input[AES_BLOCK_SIZE],
                          uint8_t output[AES_BLOCK_SIZE]);
/* Mendekripsi satu blok 16 byte menggunakan kunci pada konteks. */
void aes128_decrypt_block(const AES128Context *ctx,
                          const uint8_t input[AES_BLOCK_SIZE],
                          uint8_t output[AES_BLOCK_SIZE]);

#endif
