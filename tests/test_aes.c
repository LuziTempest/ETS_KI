#include "../src/common.h"
#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(condition, name) do { \
    if (!(condition)) { printf("GAGAL: %s\n", name); ++failures; } \
} while (0)

static void test_known_vector(void)
{
    /* Vektor publik FIPS 197 (2001), Appendix C.1, bukan master key. */
    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const uint8_t plain[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    const uint8_t expected[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };
    uint8_t encrypted[16], decrypted[16];
    AES128Context ctx;
    aes128_init(&ctx, key);
    aes128_encrypt_block(&ctx, plain, encrypted);
    CHECK(memcmp(encrypted, expected, 16) == 0, "AES encrypt vektor FIPS 197");
    aes128_decrypt_block(&ctx, expected, decrypted);
    CHECK(memcmp(decrypted, plain, 16) == 0, "AES decrypt vektor FIPS 197");
    aes128_decrypt_block(&ctx, encrypted, encrypted);
    CHECK(memcmp(encrypted, plain, 16) == 0, "AES buffer input/output sama");
}

static void test_roundtrip(void)
{
    uint8_t key[16], plain[16], encrypted[16], decrypted[16];
    AES128Context ctx;
    for (int sample = 0; sample < 256; ++sample) {
        for (int i = 0; i < 16; ++i) {
            key[i] = (uint8_t)(sample + i);
            plain[i] = (uint8_t)(sample ^ (i * 17));
        }
        aes128_init(&ctx, key);
        aes128_encrypt_block(&ctx, plain, encrypted);
        aes128_decrypt_block(&ctx, encrypted, decrypted);
        CHECK(memcmp(decrypted, plain, 16) == 0, "256 AES roundtrip");
    }
}

static void test_cbc_vector(void)
{
    /* NIST SP 800-38A F.2.1: empat blok pertama, sebelum blok PKCS#7. */
    uint8_t key[16], iv[16], plain[64], expected[64], cipher[80], restored[64];
    size_t size, cipher_size, restored_size;
    CHECK(hex_decode("2b7e151628aed2a6abf7158809cf4f3c", key, 16, &size), "CBC key");
    CHECK(hex_decode("000102030405060708090a0b0c0d0e0f", iv, 16, &size), "CBC IV");
    CHECK(hex_decode(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        plain, 64, &size), "CBC plaintext");
    CHECK(hex_decode(
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        expected, 64, &size), "CBC ciphertext");
    CHECK(cbc_encrypt(key, iv, plain, 64, cipher, sizeof(cipher), &cipher_size),
          "CBC encrypt");
    CHECK(cipher_size == 80 && memcmp(cipher, expected, 64) == 0,
          "CBC vektor NIST empat blok + blok padding");
    CHECK(cbc_decrypt(key, iv, cipher, cipher_size, restored, sizeof(restored), &restored_size) &&
          restored_size == 64 && memcmp(plain, restored, 64) == 0, "CBC decrypt");
}

static void test_padding_hex_and_limits(void)
{
    const size_t lengths[] = {0, 1, 15, 16, 17, 31, 32, 255, 1023, 1024};
    uint8_t key[16] = {0}, iv[16] = {0}, plain[MAX_TEXT + 1], restored[MAX_TEXT];
    uint8_t cipher[MAX_CIPHER], bytes[MAX_ENVELOPE];
    char hex[HEX_CAP], other[HEX_CAP];
    size_t cipher_size, restored_size, size;
    for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        size_t length = lengths[i];
        CHECK(encrypt_hex(key, plain, length, hex, sizeof(hex)), "CBC Hex encrypt");
        CHECK(decrypt_hex(key, hex, restored, sizeof(restored), &restored_size) &&
              restored_size == length && memcmp(plain, restored, length) == 0,
              "CBC roundtrip ukuran batas");
        CHECK(hex_decode(hex, bytes, sizeof(bytes), &size) &&
              size == 16 + (length / 16 + 1) * 16, "Ukuran IV dan PKCS#7");
    }
    CHECK(encrypt_hex(key, plain, 17, hex, sizeof(hex)) &&
          encrypt_hex(key, plain, 17, other, sizeof(other)) &&
          strncmp(hex, other, 32) != 0, "IV acak berbeda");
    CHECK(!encrypt_hex(key, plain, MAX_TEXT + 1, hex, sizeof(hex)), "Batas plaintext");
    CHECK(!encrypt_hex(key, plain, 17, hex, 8), "Buffer Hex terlalu kecil");
    CHECK(!hex_decode("ABC", bytes, sizeof(bytes), &size), "Hex ganjil");
    CHECK(!hex_decode("GG", bytes, sizeof(bytes), &size), "Hex tidak valid");
    CHECK(!decrypt_hex(key, "00", restored, sizeof(restored), &size), "Envelope pendek");
    CHECK(cbc_encrypt(key, iv, plain, 1, cipher, sizeof(cipher), &cipher_size), "Siapkan padding");
    iv[15] = 1; /* Mengubah padding terakhir 0x0F menjadi 0x0E: pasti tidak konsisten. */
    CHECK(!cbc_decrypt(key, iv, cipher, cipher_size, restored, sizeof(restored), &size),
          "Padding rusak ditolak");
    CHECK(!cbc_decrypt(key, iv, cipher, 15, restored, sizeof(restored), &size),
          "Ciphertext bukan kelipatan blok");
    CHECK(!cbc_decrypt(key, iv, cipher, 0, restored, sizeof(restored), &size),
          "Ciphertext kosong");
}

static void test_validation(void)
{
    uint16_t port;
    uint8_t number[4];
    char good[] = "REQ|Alice|Bob", empty[] = "REQ||Bob", extra[] = "A|B|C|D";
    char *fields[3];
    CHECK(parse_port("5000", &port) && port == 5000, "Port valid");
    CHECK(!parse_port("0", &port) && !parse_port("65536", &port) &&
          !parse_port("-1", &port) && !parse_port("5000x", &port), "Port tidak valid");
    CHECK(split_fields(good, fields, 3) == 3, "Field valid");
    CHECK(split_fields(empty, fields, 3) == -1, "Field kosong");
    CHECK(split_fields(extra, fields, 3) == -1, "Field berlebihan");
    CHECK(is_ascii_text((const uint8_t *)"Hello | Bob!", 12), "ASCII valid");
    CHECK(!is_ascii_text((const uint8_t *)"\xc3\xa9", 2), "Non-ASCII ditolak");
    write_u32(number, UINT32_MAX);
    CHECK(read_u32(number) == UINT32_MAX, "Nonce urutan byte jaringan");
    write_u32(number, 1 - 1);
    CHECK(read_u32(number) == 0, "f(N2) pada N2 minimum");
}

int main(void)
{
    test_known_vector();
    test_roundtrip();
    test_cbc_vector();
    test_padding_hex_and_limits();
    test_validation();
    if (failures != 0) return 1;
    puts("LULUS: AES FIPS 197, 256 roundtrip, CBC NIST, PKCS#7, IV, Hex, batas, validasi.");
    return 0;
}
