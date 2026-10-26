#ifndef COMMON_H
#define COMMON_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include "aes.h"

#define ID_A "Alice"
#define ID_B "Bob"
#define NONCE_SIZE 16
#define REPLY_SIZE 40  /* Ks[16] || Alice[5] || Bob[3] || N1[16] */
#define TICKET_SIZE 21 /* Ks[16] || Alice[5] */
#define TICKET_HEX_CAP 97 /* IV[16] + ciphertext[32], dalam Hex + NUL. */
#define MAX_TEXT 1024
#define MAX_CIPHER (MAX_TEXT + AES_BLOCK_SIZE)
#define MAX_ENVELOPE (AES_BLOCK_SIZE + MAX_CIPHER)
#define HEX_CAP (2 * MAX_ENVELOPE + 1)
#define PACKET_CAP 4352
#define HANDSHAKE_TIMEOUT_MS 15000

/* Menonaktifkan buffering agar keluaran program langsung tampil. */
void app_init(void);
/* Mengisi buffer dengan byte acak dari generator kriptografis Windows. */
int random_bytes(uint8_t *out, size_t size);
/* Membuat kunci sesi 16 karakter alfanumerik dengan pemilihan seragam. */
int random_session_key(uint8_t key[16]);
/* Membuat nonce acak 32 bit yang tidak bernilai nol. */
int random_nonce32(uint32_t *value);
/* Menulis bilangan 32 bit sebagai empat byte berurutan big-endian. */
void write_u32(uint8_t out[4], uint32_t value);
/* Membaca empat byte big-endian menjadi bilangan 32 bit. */
uint32_t read_u32(const uint8_t in[4]);
/* Memastikan seluruh byte merupakan karakter ASCII cetak. */
int is_ascii_text(const uint8_t *text, size_t size);
/* Membaca satu baris input; hasil 1=lengkap, 0=berhenti, -1=gagal, -2=tidak valid. */
int read_input_line(char *out, size_t cap, HANDLE stop_event, int secret);
/* Meminta dan memvalidasi master key tepat 16 karakter ASCII cetak. */
int read_master_key(const char *prompt, uint8_t key[16]);

/* Mengubah byte biner menjadi pasangan karakter heksadesimal. */
int hex_encode(const uint8_t *data, size_t size, char *hex, size_t cap);
/* Mengubah pasangan karakter heksadesimal kembali menjadi byte biner. */
int hex_decode(const char *hex, uint8_t *data, size_t cap, size_t *size);
/* Mengenkripsi data dengan AES-CBC dan padding PKCS#7 memakai IV yang diberikan. */
int cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                const uint8_t *plain, size_t size,
                uint8_t *cipher, size_t cap, size_t *cipher_size);
/* Mendekripsi AES-CBC dan memeriksa padding PKCS#7 sebelum mengembalikan plaintext. */
int cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                const uint8_t *cipher, size_t size,
                uint8_t *plain, size_t cap, size_t *plain_size);
/* Membuat IV acak dan mengemas IV serta ciphertext CBC sebagai teks Hex. */
int encrypt_hex(const uint8_t key[16], const uint8_t *plain, size_t size,
                char *hex, size_t cap);
/* Memisahkan IV dari ciphertext Hex lalu mendekripsi isinya. */
int decrypt_hex(const uint8_t key[16], const char *hex,
                uint8_t *plain, size_t cap, size_t *plain_size);
/* Menampilkan label dan data terenkripsi dalam format Hex(IV||ciphertext). */
void log_cipher(const char *label, const char *hex);

/* Mengaktifkan Winsock sebelum program memakai jaringan. */
int net_init(void);
/* Memvalidasi teks nomor port TCP dalam rentang 1 sampai 65535. */
int parse_port(const char *text, uint16_t *port);
/* Memeriksa apakah teks berisi alamat IPv4 yang valid. */
int valid_ipv4(const char *ip);
/* Membuka socket TCP yang mendengarkan koneksi pada port tertentu. */
SOCKET listen_tcp(uint16_t port);
/* Menghubungkan socket TCP ke alamat IPv4 dan port tujuan. */
SOCKET connect_tcp(const char *ip, uint16_t port);
/* Mengatur batas waktu pengiriman dan penerimaan pada socket. */
int socket_timeouts(SOCKET socket, DWORD receive_ms);
/* Mengirim seluruh byte meskipun satu panggilan send hanya mengirim sebagian. */
int send_all(SOCKET socket, const char *data, size_t size);
/* Mengirim paket ASCII yang diakhiri karakter baris baru. */
int send_packet(SOCKET socket, const char *packet);
/* Menerima satu paket; hasil 1=lengkap, 0=peer tutup, -1=gagal/tidak valid. */
int recv_packet(SOCKET socket, char *packet, size_t cap);
/* Memisahkan paket berdasarkan tanda | menjadi sejumlah field. */
int split_fields(char *packet, char **fields, int max_fields);
/* Menerima paket dan memastikan jenis serta jumlah field sesuai harapan. */
int expect_packet(SOCKET socket, const char *type, char *packet,
                  size_t cap, char **fields, int count);
/* Mengenkripsi isi, membentuk paket bertipe tertentu, lalu mengirimkannya. */
int send_encrypted(SOCKET socket, const char *type, const uint8_t key[16],
                   const uint8_t *plain, size_t size, const char *label);
/* Mengakhiri komunikasi dan menutup socket yang masih valid. */
void close_connection(SOCKET socket);

/* Menandai penyebab berakhirnya chat atau permintaan kunci sesi baru. */
enum ChatResult { CHAT_ENDED, CHAT_REKEY, CHAT_QUIT };
/* Menjalankan chat dua arah dan menangani perintah keluar atau pembaruan kunci. */
enum ChatResult run_chat(SOCKET socket, const uint8_t key[16], int is_alice);

#endif
