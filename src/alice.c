#include "common.h"
#include <stdio.h>
#include <string.h>

// Meminta Ks dan tiket ke KDC, lalu memverifikasi identitas serta nonce dalam balasan.
static int request_session(const char *ip, uint16_t port, const uint8_t ka[16],
                           uint8_t ks[16], char ticket[TICKET_HEX_CAP])
{
    SOCKET kdc = INVALID_SOCKET;
    char packet[PACKET_CAP], nonce_hex[33], *fields[3];
    uint8_t nonce[NONCE_SIZE], reply[REPLY_SIZE] = {0}, opaque_ticket[48];
    size_t size;
    int ok = 0;
    if (!random_bytes(nonce, sizeof(nonce)) ||
        !hex_encode(nonce, sizeof(nonce), nonce_hex, sizeof(nonce_hex))) goto done;
    kdc = connect_tcp(ip, port);
    if (kdc == INVALID_SOCKET) goto done;
    snprintf(packet, sizeof(packet), "REQUEST|%s|%s|%s", ID_A, ID_B, nonce_hex);
    printf("[STEP 1] Alice -> KDC: Alice | Bob | N1=%s\n", nonce_hex);
    if (!send_packet(kdc, packet) ||
        !expect_packet(kdc, "KEYS", packet, sizeof(packet), fields, 3)) goto done;
    log_cipher("[STEP 2] KDC -> Alice, bagian Ka", fields[1]);
    log_cipher("[STEP 2] KDC -> Alice, tiket Kb (diteruskan tanpa dibuka)", fields[2]);
    if (!decrypt_hex(ka, fields[1], reply, sizeof(reply), &size) ||
        size != REPLY_SIZE || memcmp(reply + 16, ID_A, 5) != 0 ||
        memcmp(reply + 21, ID_B, 3) != 0 ||
        memcmp(reply + 24, nonce, NONCE_SIZE) != 0 || !is_ascii_text(reply, 16)) {
        fputs("Balasan KDC ditolak: periksa Ka; ID_A, ID_B, dan N1 harus cocok.\n", stderr);
        goto done;
    }
    if (!hex_decode(fields[2], opaque_ticket, sizeof(opaque_ticket), &size) ||
        size != sizeof(opaque_ticket)) {
        fputs("Format tiket dari KDC tidak valid.\n", stderr);
        goto done;
    }
    memcpy(ks, reply, 16);
    memcpy(ticket, fields[2], TICKET_HEX_CAP);
    puts("[STEP 2] ID_A, ID_B, dan N1 cocok.");
    ok = 1;
done:
    close_connection(kdc);
    SecureZeroMemory(reply, sizeof(reply));
    return ok;
}

// Mengirim tiket ke Bob dan membuktikan penguasaan Ks lewat tantangan N2.
static int authenticate_bob(SOCKET bob, const uint8_t ks[16], const char *ticket)
{
    char packet[PACKET_CAP], *fields[2];
    uint8_t challenge[4], response[4], ready[9];
    uint32_t n2;
    size_t size;
    snprintf(packet, sizeof(packet), "TICKET|%s", ticket);
    log_cipher("[STEP 3] Alice -> Bob, tiket Kb", ticket);
    if (!send_packet(bob, packet) ||
        !expect_packet(bob, "CHALLENGE", packet, sizeof(packet), fields, 2)) return 0;
    log_cipher("[STEP 4] Bob -> Alice, E(Ks,N2)", fields[1]);
    if (!decrypt_hex(ks, fields[1], challenge, sizeof(challenge), &size) ||
        size != 4 || (n2 = read_u32(challenge)) == 0) {
        fputs("Challenge Bob tidak valid; autentikasi dibatalkan.\n", stderr);
        return 0;
    }
    write_u32(response, n2 - 1);
    if (!send_encrypted(bob, "RESPONSE", ks, response, sizeof(response),
                        "[STEP 5] Alice -> Bob, E(Ks,N2-1)") ||
        !expect_packet(bob, "READY", packet, sizeof(packet), fields, 2)) return 0;
    log_cipher("[READY] Bob -> Alice", fields[1]);
    if (!decrypt_hex(ks, fields[1], ready, sizeof(ready), &size) ||
        size != sizeof(ready) || memcmp(ready, "READY", 5) != 0 ||
        memcmp(ready + 5, challenge, 4) != 0) {
        fputs("Konfirmasi penerimaan Bob tidak valid; chat tidak dimulai.\n", stderr);
        return 0;
    }
    puts("[STEP 5] Bob mengonfirmasi autentikasi berhasil.");
    return 1;
}

// Membaca pilihan pengguna untuk meminta sesi baru atau keluar.
static int ask_retry(void)
{
    char input[32];
    for (;;) {
        int result;
        puts("Ketik /rekey untuk meminta sesi baru, atau /quit untuk keluar:");
        result = read_input_line(input, sizeof(input), NULL, 0);
        if (result == 0 || result == -1) return 0;
        if (result == 1 && strcmp(input, "/quit") == 0) return 0;
        if (result == 1 && strcmp(input, "/rekey") == 0) return 1;
        puts("Perintah tidak valid.");
    }
}

// Menjalankan alur Alice dari permintaan Ks hingga autentikasi dan chat dengan Bob.
int main(int argc, char **argv)
{
    uint16_t kdc_port, bob_port;
    uint8_t ka[16] = {0}, ks[16] = {0};
    char ticket[TICKET_HEX_CAP];
    int exit_code = 1;
    app_init();
    if (argc != 5 || !parse_port(argv[2], &kdc_port) || !parse_port(argv[4], &bob_port)) {
        fputs("Pemakaian: bin\\alice.exe <IPv4_KDC> <port_KDC> <IPv4_Bob> <port_Bob>\n"
              "Port harus 1..65535.\n", stderr);
        return 1;
    }
    if (!net_init()) return 1;
    if (!valid_ipv4(argv[1]) || !valid_ipv4(argv[3])) {
        fputs("IP tidak valid: gunakan alamat IPv4, bukan hostname.\n", stderr);
        goto done;
    }
    if (!read_master_key("Masukkan Ka (sama dengan KDC)", ka)) goto done;
    for (;;) {
        SOCKET bob = INVALID_SOCKET;
        enum ChatResult result = CHAT_ENDED;
        puts("Memulai distribusi dan autentikasi kunci.");
        if (request_session(argv[1], kdc_port, ka, ks, ticket)) {
            bob = connect_tcp(argv[3], bob_port);
            if (bob != INVALID_SOCKET && authenticate_bob(bob, ks, ticket))
                result = run_chat(bob, ks, 1);
        }
        close_connection(bob);
        SecureZeroMemory(ks, sizeof(ks));
        if (result == CHAT_QUIT) break;
        if (result == CHAT_REKEY) {
            puts("[REKEY] Sesi lama ditutup; meminta Ks baru dan mengulang STEP 1..5.");
            continue;
        }
        puts("Sesi berakhir atau belum berhasil.");
        if (!ask_retry()) break;
    }
    exit_code = 0;
done:
    SecureZeroMemory(ka, sizeof(ka));
    SecureZeroMemory(ks, sizeof(ks));
    WSACleanup();
    return exit_code;
}
