#include "common.h"
#include <bcrypt.h>
#include <limits.h>
#include <process.h>
#include <stdio.h>
#include <string.h>

/* Menonaktifkan buffering agar keluaran program langsung tampil. */
void app_init(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

/* Mengisi buffer dengan byte acak dari generator kriptografis Windows. */
int random_bytes(uint8_t *out, size_t size)
{
    if (size > ULONG_MAX ||
        BCryptGenRandom(NULL, out, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        fputs("Gagal memperoleh bilangan acak dari Windows.\n", stderr);
        return 0;
    }
    return 1;
}

/* Membuat kunci sesi 16 karakter alfanumerik dengan pemilihan seragam. */
int random_session_key(uint8_t key[16])
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    size_t used = 0;
    while (used < 16) {
        uint8_t value;
        if (!random_bytes(&value, 1)) return 0;
        /* 248 habis dibagi 62: rejection sampling menghindari modulo bias. */
        if (value < 248) key[used++] = (uint8_t)alphabet[value % 62];
    }
    return 1;
}

/* Membuat nonce acak 32 bit yang tidak bernilai nol. */
int random_nonce32(uint32_t *value)
{
    do {
        if (!random_bytes((uint8_t *)value, sizeof(*value))) return 0;
    } while (*value == 0);
    return 1;
}

/* Menulis bilangan 32 bit sebagai empat byte berurutan big-endian. */
void write_u32(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

/* Membaca empat byte big-endian menjadi bilangan 32 bit. */
uint32_t read_u32(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

/* Memastikan seluruh byte merupakan karakter ASCII cetak. */
int is_ascii_text(const uint8_t *text, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        if (text[i] < 32 || text[i] > 126) return 0;
    return 1;
}

/* Membaca satu baris input, memvalidasi ASCII, dan menyembunyikan input rahasia. */
int read_input_line(char *out, size_t cap, HANDLE stop_event, int secret)
{
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD original_mode = 0, read_count;
    int console = GetConsoleMode(input, &original_mode) != 0;
    int invalid = 0, result = 0;
    size_t used = 0;
    if (cap == 0) return -1;
    out[0] = '\0';
    if (console && !SetConsoleMode(input, original_mode &
                                  ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT))) return -1;
    for (;;) {
        unsigned int character;
        if (stop_event && WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0)
            break;
        if (console) {
            INPUT_RECORD event;
            HANDLE handles[2] = {input, stop_event};
            DWORD wait = WaitForMultipleObjects(stop_event ? 2 : 1, handles, FALSE, INFINITE);
            if (wait != WAIT_OBJECT_0) {
                if (wait == WAIT_FAILED) result = -1;
                break;
            }
            if (!ReadConsoleInputW(input, &event, 1, &read_count)) {
                result = -1;
                break;
            }
            if (event.EventType != KEY_EVENT || !event.Event.KeyEvent.bKeyDown)
                continue;
            character = event.Event.KeyEvent.uChar.UnicodeChar;
            if (character == 0) continue;
            if (character == '\r') character = '\n';
            if (character == '\b') {
                if (used > 0) {
                    --used;
                    if (!secret) fputs("\b \b", stdout);
                }
                continue;
            }
        } else {
            unsigned char byte;
            if (GetFileType(input) == FILE_TYPE_PIPE) {
                DWORD available = 0;
                if (!PeekNamedPipe(input, NULL, 0, NULL, &available, NULL)) break;
                if (available == 0) {
                    if (stop_event) WaitForSingleObject(stop_event, 25);
                    else Sleep(25);
                    continue;
                }
            }
            if (!ReadFile(input, &byte, 1, &read_count, NULL) || read_count == 0) break;
            character = byte;
            if (character == '\r') continue;
        }
        if (character == '\n') {
            result = invalid ? -2 : 1;
            break;
        }
        if (character < 32 || character > 126 || used + 1 >= cap) {
            invalid = 1; /* Habiskan baris agar sisa input tidak menjadi pesan baru. */
            continue;
        }
        out[used++] = (char)character;
        if (console && !secret) putchar((int)character);
    }
    out[used] = '\0';
    if (console) {
        SetConsoleMode(input, original_mode);
        putchar('\n');
    }
    return result;
}

/* Meminta dan memvalidasi master key tepat 16 karakter ASCII cetak. */
int read_master_key(const char *prompt, uint8_t key[16])
{
    char input[18];
    for (;;) {
        int result;
        printf("%s (tepat 16 karakter ASCII cetak; input disembunyikan): ", prompt);
        result = read_input_line(input, sizeof(input), NULL, 1);
        if (result == 0 || result == -1) {
            SecureZeroMemory(input, sizeof(input));
            fputs("Input key berakhir atau tidak dapat dibaca.\n", stderr);
            return 0;
        }
        if (result == 1 && strlen(input) == 16) {
            memcpy(key, input, 16);
            SecureZeroMemory(input, sizeof(input));
            return 1;
        }
        SecureZeroMemory(input, sizeof(input));
        puts("Key harus tepat 16 karakter ASCII cetak (spasi sampai ~), tanpa Enter.");
    }
}

/* Mengubah byte biner menjadi pasangan karakter heksadesimal. */
int hex_encode(const uint8_t *data, size_t size, char *hex, size_t cap)
{
    static const char digits[] = "0123456789ABCDEF";
    if (cap == 0 || size > (cap - 1) / 2) return 0;
    for (size_t i = 0; i < size; ++i) {
        hex[2 * i] = digits[data[i] >> 4];
        hex[2 * i + 1] = digits[data[i] & 15];
    }
    hex[2 * size] = '\0';
    return 1;
}

/* Mengubah satu karakter heksadesimal menjadi nilai 0 sampai 15. */
static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Mengubah pasangan karakter heksadesimal kembali menjadi byte biner. */
int hex_decode(const char *hex, uint8_t *data, size_t cap, size_t *size)
{
    size_t length = strlen(hex);
    *size = 0;
    if (length % 2 != 0 || length / 2 > cap) return 0;
    for (size_t i = 0; i < length / 2; ++i) {
        int high = hex_digit(hex[2 * i]), low = hex_digit(hex[2 * i + 1]);
        if (high < 0 || low < 0) return 0;
        data[i] = (uint8_t)((high << 4) | low);
    }
    *size = length / 2;
    return 1;
}

/* Mengenkripsi data dengan AES-CBC dan padding PKCS#7 memakai IV yang diberikan. */
int cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                const uint8_t *plain, size_t size,
                uint8_t *cipher, size_t cap, size_t *cipher_size)
{
    AES128Context ctx;
    uint8_t block[16], previous[16];
    size_t padded;
    *cipher_size = 0;
    if (size > MAX_TEXT) return 0;
    padded = (size / 16 + 1) * 16;
    if (cap < padded) return 0;
    aes128_init(&ctx, key);
    memcpy(previous, iv, 16);
    for (size_t offset = 0; offset < padded; offset += 16) {
        for (size_t i = 0; i < 16; ++i) {
            size_t pos = offset + i;
            uint8_t value = pos < size ? plain[pos] : (uint8_t)(padded - size);
            block[i] = value ^ previous[i];
        }
        aes128_encrypt_block(&ctx, block, cipher + offset);
        memcpy(previous, cipher + offset, 16);
    }
    SecureZeroMemory(&ctx, sizeof(ctx));
    SecureZeroMemory(block, sizeof(block));
    *cipher_size = padded;
    return 1;
}

/* Mendekripsi AES-CBC dan memeriksa padding PKCS#7 sebelum mengembalikan plaintext. */
int cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                const uint8_t *cipher, size_t size,
                uint8_t *plain, size_t cap, size_t *plain_size)
{
    AES128Context ctx;
    uint8_t padded[MAX_CIPHER], previous[16];
    size_t length;
    int ok = 0;
    *plain_size = 0;
    if (size == 0 || size > MAX_CIPHER || size % 16 != 0) return 0;
    aes128_init(&ctx, key);
    memcpy(previous, iv, 16);
    for (size_t offset = 0; offset < size; offset += 16) {
        aes128_decrypt_block(&ctx, cipher + offset, padded + offset);
        for (size_t i = 0; i < 16; ++i) padded[offset + i] ^= previous[i];
        memcpy(previous, cipher + offset, 16);
    }
    uint8_t padding = padded[size - 1];
    if (padding == 0 || padding > 16) goto done;
    for (size_t i = 0; i < padding; ++i)
        if (padded[size - 1 - i] != padding) goto done;
    length = size - padding;
    if (length > cap || length > MAX_TEXT) goto done;
    memcpy(plain, padded, length);
    *plain_size = length;
    ok = 1;
done:
    SecureZeroMemory(&ctx, sizeof(ctx));
    SecureZeroMemory(padded, sizeof(padded));
    return ok;
}

/* Membuat IV acak dan mengemas IV serta ciphertext CBC sebagai teks Hex. */
int encrypt_hex(const uint8_t key[16], const uint8_t *plain, size_t size,
                char *hex, size_t cap)
{
    uint8_t envelope[MAX_ENVELOPE];
    size_t length;
    if (!random_bytes(envelope, 16) ||
        !cbc_encrypt(key, envelope, plain, size, envelope + 16,
                     sizeof(envelope) - 16, &length)) return 0;
    return hex_encode(envelope, 16 + length, hex, cap);
}

/* Memisahkan IV dari ciphertext Hex lalu mendekripsi isinya. */
int decrypt_hex(const uint8_t key[16], const char *hex,
                uint8_t *plain, size_t cap, size_t *plain_size)
{
    uint8_t envelope[MAX_ENVELOPE];
    size_t length;
    *plain_size = 0;
    if (!hex_decode(hex, envelope, sizeof(envelope), &length) ||
        length < 32 || length % 16 != 0) return 0;
    return cbc_decrypt(key, envelope, envelope + 16, length - 16, plain, cap, plain_size);
}

/* Menampilkan label dan data terenkripsi dalam format Hex(IV||ciphertext). */
void log_cipher(const char *label, const char *hex)
{
    printf("%s Hex(IV||ciphertext): %s\n", label, hex);
}

/* Mengaktifkan Winsock sebelum program memakai jaringan. */
int net_init(void)
{
    WSADATA data;
    int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        fprintf(stderr, "WSAStartup gagal: %d.\n", result);
        return 0;
    }
    return 1;
}

/* Memvalidasi teks nomor port TCP dalam rentang 1 sampai 65535. */
int parse_port(const char *text, uint16_t *port)
{
    unsigned long value = 0;
    if (*text == '\0') return 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9') return 0;
        value = value * 10 + (unsigned)(*p - '0');
        if (value > 65535) return 0;
    }
    if (value == 0) return 0;
    *port = (uint16_t)value;
    return 1;
}

/* Memeriksa apakah teks berisi alamat IPv4 yang valid. */
int valid_ipv4(const char *ip)
{
    struct in_addr address;
    return InetPtonA(AF_INET, ip, &address) == 1;
}

/* Menampilkan operasi jaringan yang gagal beserta kode kesalahan Winsock. */
static void network_error(const char *operation)
{
    fprintf(stderr, "%s gagal (Winsock %d). Periksa IP, port, firewall, dan koneksi.\n",
            operation, WSAGetLastError());
}

/* Mengatur batas waktu pengiriman dan penerimaan pada socket. */
int socket_timeouts(SOCKET socket, DWORD receive_ms)
{
    DWORD send_ms = HANDSHAKE_TIMEOUT_MS;
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&receive_ms,
                   sizeof(receive_ms)) == SOCKET_ERROR ||
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_ms,
                   sizeof(send_ms)) == SOCKET_ERROR) {
        network_error("Mengatur timeout");
        return 0;
    }
    return 1;
}

/* Membuka socket TCP yang mendengarkan koneksi pada port tertentu. */
SOCKET listen_tcp(uint16_t port)
{
    struct sockaddr_in address = {0};
    BOOL exclusive = TRUE;
    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) {
        network_error("Membuat socket");
        return INVALID_SOCKET;
    }
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (setsockopt(server, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   (const char *)&exclusive, sizeof(exclusive)) == SOCKET_ERROR ||
        bind(server, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR ||
        listen(server, 4) == SOCKET_ERROR) {
        network_error("Bind/listen (port mungkin sudah dipakai)");
        closesocket(server);
        return INVALID_SOCKET;
    }
    return server;
}

/* Menghubungkan socket TCP ke alamat IPv4 dan port tujuan. */
SOCKET connect_tcp(const char *ip, uint16_t port)
{
    struct sockaddr_in address = {0};
    SOCKET connection;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1) {
        fprintf(stderr, "IP tidak valid: gunakan IPv4 seperti 192.168.1.10.\n");
        return INVALID_SOCKET;
    }
    connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connection == INVALID_SOCKET) {
        network_error("Membuat socket");
        return INVALID_SOCKET;
    }
    if (!socket_timeouts(connection, HANDSHAKE_TIMEOUT_MS) ||
        connect(connection, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
        network_error("Menghubungi server");
        closesocket(connection);
        return INVALID_SOCKET;
    }
    return connection;
}

/* Mengirim seluruh byte meskipun satu panggilan send hanya mengirim sebagian. */
int send_all(SOCKET socket, const char *data, size_t size)
{
    size_t sent = 0;
    while (sent < size) {
        int result = send(socket, data + sent, (int)(size - sent), 0);
        if (result == SOCKET_ERROR || result == 0) {
            network_error("Mengirim data");
            return 0;
        }
        sent += (size_t)result;
    }
    return 1;
}

/* Mengirim paket ASCII yang diakhiri karakter baris baru. */
int send_packet(SOCKET socket, const char *packet)
{
    size_t size = strlen(packet);
    if (size == 0 || size >= PACKET_CAP ||
        !is_ascii_text((const uint8_t *)packet, size)) return 0;
    return send_all(socket, packet, size) && send_all(socket, "\n", 1);
}

/* Menerima satu paket ASCII hingga baris baru dengan pemeriksaan panjang. */
int recv_packet(SOCKET socket, char *packet, size_t cap)
{
    size_t used = 0;
    if (cap == 0) return -1;
    packet[0] = '\0';
    /* Satu byte per recv menjaga batas baris tanpa buffer/state jaringan tambahan. */
    for (;;) {
        char byte;
        int result = recv(socket, &byte, 1, 0);
        if (result == 0) {
            if (used != 0) fputs("Koneksi putus di tengah paket.\n", stderr);
            return used == 0 ? 0 : -1;
        }
        if (result == SOCKET_ERROR) {
            network_error("Menerima data (koneksi putus atau timeout)");
            return -1;
        }
        if (byte == '\n') {
            packet[used] = '\0';
            return used != 0 ? 1 : -1;
        }
        if ((unsigned char)byte < 32 || (unsigned char)byte > 126 ||
            used + 1 >= cap || used + 1 >= PACKET_CAP) {
            fputs("Paket ditolak: terlalu panjang atau karakter tidak valid.\n", stderr);
            return -1;
        }
        packet[used++] = byte;
    }
}

/* Memisahkan paket berdasarkan tanda | menjadi sejumlah field. */
int split_fields(char *packet, char **fields, int max_fields)
{
    int count = 0;
    char *start = packet;
    for (char *p = packet; ; ++p) {
        if (*p == '|' || *p == '\0') {
            char end = *p;
            if (p == start || count >= max_fields) return -1;
            *p = '\0';
            fields[count++] = start;
            if (end == '\0') return count;
            start = p + 1;
        }
    }
}

/* Menerima paket dan memastikan jenis serta jumlah field sesuai harapan. */
int expect_packet(SOCKET socket, const char *type, char *packet,
                  size_t cap, char **fields, int count)
{
    if (recv_packet(socket, packet, cap) != 1) {
        fputs("Paket yang diharapkan tidak diterima; sesi dibatalkan.\n", stderr);
        return 0;
    }
    int actual = split_fields(packet, fields, count);
    if (actual != count || strcmp(fields[0], type) != 0) {
        fputs("Paket tidak sesuai urutan/format atau peer menolak autentikasi.\n", stderr);
        return 0;
    }
    return 1;
}

/* Mengenkripsi isi, membentuk paket bertipe tertentu, lalu mengirimkannya. */
int send_encrypted(SOCKET socket, const char *type, const uint8_t key[16],
                   const uint8_t *plain, size_t size, const char *label)
{
    char hex[HEX_CAP], packet[PACKET_CAP];
    if (!encrypt_hex(key, plain, size, hex, sizeof(hex))) return 0;
    int length = snprintf(packet, sizeof(packet), "%s|%s", type, hex);
    if (length < 0 || (size_t)length >= sizeof(packet)) return 0;
    log_cipher(label, hex);
    return send_packet(socket, packet);
}

/* Mengakhiri komunikasi dan menutup socket yang masih valid. */
void close_connection(SOCKET socket)
{
    if (socket != INVALID_SOCKET) {
        shutdown(socket, SD_BOTH);
        closesocket(socket);
    }
}

typedef struct {
    SOCKET socket;
    const uint8_t *key;
    HANDLE stopped;
    int is_alice;
} ChatContext;

/* Menerima, mendekripsi, dan menampilkan pesan chat atau perintah penutupan. */
static unsigned __stdcall chat_receiver(void *argument)
{
    ChatContext *chat = argument;
    char packet[PACKET_CAP], *fields[2];
    uint8_t plain[MAX_TEXT + 1];
    const char *peer = chat->is_alice ? ID_B : ID_A;
    while (WaitForSingleObject(chat->stopped, 0) != WAIT_OBJECT_0) {
        size_t size;
        int result = recv_packet(chat->socket, packet, sizeof(packet));
        if (result != 1) {
            if (WaitForSingleObject(chat->stopped, 0) != WAIT_OBJECT_0)
                puts("\nPeer menutup koneksi atau jaringan terputus.");
            break;
        }
        if (split_fields(packet, fields, 2) != 2 ||
            (strcmp(fields[0], "CHAT") != 0 && strcmp(fields[0], "CLOSE") != 0)) {
            fputs("\nPaket chat tidak valid; sesi ditutup.\n", stderr);
            break;
        }
        log_cipher(strcmp(fields[0], "CHAT") == 0 ? "\n[CHAT RX]" : "\n[CLOSE RX]", fields[1]);
        if (!decrypt_hex(chat->key, fields[1], plain, MAX_TEXT, &size) ||
            size == 0 || !is_ascii_text(plain, size)) {
            fputs("Dekripsi/format pesan gagal; sesi ditutup.\n", stderr);
            break;
        }
        plain[size] = '\0';
        if (strcmp(fields[0], "CLOSE") == 0) {
            if (!chat->is_alice && strcmp((char *)plain, "REKEY") == 0)
                puts("[REKEY] Alice mengakhiri sesi; Bob akan menunggu tiket baru.");
            else if (strcmp((char *)plain, "QUIT") == 0)
                printf("%s mengakhiri chat.\n", peer);
            else
                fputs("Perintah penutupan tidak valid.\n", stderr);
            break;
        }
        printf("%s (plaintext): %s\n", peer, plain);
    }
    SecureZeroMemory(plain, sizeof(plain));
    SetEvent(chat->stopped);
    shutdown(chat->socket, SD_BOTH);
    return 0;
}

/* Menjalankan chat dua arah dan menangani perintah keluar atau pembaruan kunci. */
enum ChatResult run_chat(SOCKET socket, const uint8_t key[16], int is_alice)
{
    ChatContext chat = {socket, key, NULL, is_alice};
    char input[MAX_TEXT + 1];
    HANDLE receiver;
    enum ChatResult result = CHAT_ENDED;
    if (!socket_timeouts(socket, 0)) return result;
    chat.stopped = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!chat.stopped) {
        fputs("Gagal membuat event chat.\n", stderr);
        return result;
    }
    receiver = (HANDLE)_beginthreadex(NULL, 0, chat_receiver, &chat, 0, NULL);
    if (!receiver) {
        fputs("Gagal membuat thread penerima.\n", stderr);
        CloseHandle(chat.stopped);
        return result;
    }
    puts("[CHAT] Sesi aktif. Ketik pesan ASCII (maksimal 1024 karakter) lalu Enter.");
    puts(is_alice ? "Perintah: /rekey untuk Ks baru, /quit untuk keluar."
                  : "Perintah: /quit untuk keluar dari Bob. /rekey dilakukan oleh Alice.");
    while (WaitForSingleObject(chat.stopped, 0) != WAIT_OBJECT_0) {
        int read_result = read_input_line(input, sizeof(input), chat.stopped, 0);
        if (WaitForSingleObject(chat.stopped, 0) == WAIT_OBJECT_0) break;
        if (read_result == -2) {
            puts("Pesan ditolak: gunakan ASCII cetak saja (spasi sampai ~), maksimal 1024 karakter.");
            continue;
        }
        if (read_result <= 0 || strcmp(input, "/quit") == 0) {
            send_encrypted(socket, "CLOSE", key, (const uint8_t *)"QUIT", 4, "[CLOSE TX]");
            result = CHAT_QUIT;
            break;
        }
        if (strcmp(input, "/rekey") == 0) {
            if (!is_alice) {
                puts("Hanya Alice yang dapat meminta /rekey.");
                continue;
            }
            send_encrypted(socket, "CLOSE", key, (const uint8_t *)"REKEY", 5, "[CLOSE TX]");
            result = CHAT_REKEY;
            break;
        }
        if (input[0] == '\0') continue;
        if (!send_encrypted(socket, "CHAT", key, (const uint8_t *)input, strlen(input),
                            "[CHAT TX]")) {
            fputs("Pesan tidak terkirim; sesi ditutup.\n", stderr);
            break;
        }
    }
    SecureZeroMemory(input, sizeof(input));
    SetEvent(chat.stopped);
    /* FIN setelah paket CLOSE; beri peer kesempatan membaca sebelum socket ditutup. */
    shutdown(socket, SD_SEND);
    if (WaitForSingleObject(receiver, 2000) != WAIT_OBJECT_0) {
        shutdown(socket, SD_BOTH); /* Membatalkan recv yang masih menunggu peer. */
        WaitForSingleObject(receiver, INFINITE);
    }
    CloseHandle(receiver);
    CloseHandle(chat.stopped);
    /* Pemilik socket menutupnya setelah thread selesai; tidak ada use-after-close. */
    return result;
}
