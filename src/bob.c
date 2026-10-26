#include "common.h"
#include <stdio.h>
#include <string.h>

// Membuka tiket Alice, menguji jawaban N2 - 1, lalu mengonfirmasi sesi.
static int authenticate_alice(SOCKET alice, const uint8_t kb[16], uint8_t ks[16])
{
    char packet[PACKET_CAP], *fields[2];
    uint8_t ticket[TICKET_SIZE] = {0}, challenge[4], response[4], ready[9];
    uint32_t n2;
    size_t size;
    int ok = 0;
    if (!expect_packet(alice, "TICKET", packet, sizeof(packet), fields, 2)) goto done;
    log_cipher("[STEP 3] Alice -> Bob, tiket Kb", fields[1]);
    if (!decrypt_hex(kb, fields[1], ticket, sizeof(ticket), &size) ||
        size != TICKET_SIZE || memcmp(ticket + 16, ID_A, 5) != 0 ||
        !is_ascii_text(ticket, 16)) {
        fputs("Tiket ditolak: periksa kesamaan Kb pada Bob dan KDC serta ID_A.\n", stderr);
        goto done;
    }
    memcpy(ks, ticket, 16);
    if (!random_nonce32(&n2)) goto done;
    write_u32(challenge, n2);
    if (!send_encrypted(alice, "CHALLENGE", ks, challenge, sizeof(challenge),
                        "[STEP 4] Bob -> Alice, E(Ks,N2)")) goto done;
    if (!expect_packet(alice, "RESPONSE", packet, sizeof(packet), fields, 2)) goto done;
    log_cipher("[STEP 5] Alice -> Bob, E(Ks,N2-1)", fields[1]);
    if (!decrypt_hex(ks, fields[1], response, sizeof(response), &size) ||
        size != 4 || read_u32(response) != n2 - 1) {
        fputs("Autentikasi gagal: jawaban harus tepat N2 - 1.\n", stderr);
        goto done;
    }
    puts("[STEP 5] Jawaban N2 - 1 benar; sesi diterima.");
    memcpy(ready, "READY", 5);
    memcpy(ready + 5, challenge, 4);
    ok = send_encrypted(alice, "READY", ks, ready, sizeof(ready),
                        "[READY] Bob -> Alice");
done:
    if (!ok) {
        send_packet(alice, "ERROR|Autentikasi gagal");
        SecureZeroMemory(ks, 16);
    }
    SecureZeroMemory(ticket, sizeof(ticket));
    return ok;
}

// Menjalankan server Bob untuk menerima autentikasi dan chat dari Alice.
int main(int argc, char **argv)
{
    uint16_t port;
    uint8_t kb[16] = {0}, ks[16] = {0};
    SOCKET server = INVALID_SOCKET;
    int exit_code = 1;
    app_init();
    if (argc != 2 || !parse_port(argv[1], &port)) {
        fputs("Pemakaian: bin\\bob.exe <port 1..65535>\n", stderr);
        return 1;
    }
    if (!net_init()) return 1;
    if (!read_master_key("Masukkan Kb (sama dengan KDC)", kb)) goto done;
    server = listen_tcp(port);
    if (server == INVALID_SOCKET) goto done;
    printf("Bob siap di 0.0.0.0:%u. Ctrl+C untuk berhenti saat menunggu.\n", (unsigned)port);
    for (;;) {
        enum ChatResult result = CHAT_ENDED;
        SOCKET alice;
        puts("Bob menunggu sesi Alice.");
        alice = accept(server, NULL, NULL);
        if (alice == INVALID_SOCKET) {
            fprintf(stderr, "Accept Bob gagal (Winsock %d).\n", WSAGetLastError());
            break;
        }
        if (socket_timeouts(alice, HANDSHAKE_TIMEOUT_MS) &&
            authenticate_alice(alice, kb, ks)) {
            result = run_chat(alice, ks, 0);
        }
        close_connection(alice);
        SecureZeroMemory(ks, sizeof(ks));
        if (result == CHAT_QUIT) {
            exit_code = 0;
            break;
        }
    }
done:
    close_connection(server);
    SecureZeroMemory(kb, sizeof(kb));
    SecureZeroMemory(ks, sizeof(ks));
    WSACleanup();
    return exit_code;
}
