#include "common.h"
#include <stdio.h>
#include <string.h>

// Memvalidasi permintaan Alice, membuat Ks, lalu mengirim balasan dan tiket terenkripsi.
static int handle_request(SOCKET client, const uint8_t ka[16], const uint8_t kb[16])
{
    char packet[PACKET_CAP], *fields[4];
    char reply_hex[129], ticket_hex[TICKET_HEX_CAP];
    uint8_t nonce[NONCE_SIZE], reply[REPLY_SIZE] = {0}, ticket[TICKET_SIZE] = {0};
    size_t nonce_size;
    int ok = 0;

    if (!expect_packet(client, "REQUEST", packet, sizeof(packet), fields, 4) ||
        strcmp(fields[1], ID_A) != 0 || strcmp(fields[2], ID_B) != 0 ||
        !hex_decode(fields[3], nonce, sizeof(nonce), &nonce_size) ||
        nonce_size != NONCE_SIZE) {
        fputs("Permintaan ditolak: ID atau N1 tidak valid.\n", stderr);
        goto done;
    }
    printf("[STEP 1] Alice -> KDC: Alice | Bob | N1=%s\n", fields[3]);

    if (!random_session_key(reply)) goto done;
    memcpy(reply + 16, ID_A, 5);
    memcpy(reply + 21, ID_B, 3);
    memcpy(reply + 24, nonce, NONCE_SIZE);
    memcpy(ticket, reply, 16);
    memcpy(ticket + 16, ID_A, 5);
    if (!encrypt_hex(ka, reply, sizeof(reply), reply_hex, sizeof(reply_hex)) ||
        !encrypt_hex(kb, ticket, sizeof(ticket), ticket_hex, sizeof(ticket_hex))) goto done;

    log_cipher("[STEP 2] KDC -> Alice, bagian Ka", reply_hex);
    log_cipher("[STEP 2] KDC -> Alice, tiket Kb", ticket_hex);
    snprintf(packet, sizeof(packet), "KEYS|%s|%s", reply_hex, ticket_hex);
    ok = send_packet(client, packet);
    if (ok) puts("Ks baru telah dibuat dan dikirim dalam dua bagian terenkripsi.");
done:
    if (!ok) send_packet(client, "ERROR|Permintaan KDC gagal");
    SecureZeroMemory(reply, sizeof(reply));
    SecureZeroMemory(ticket, sizeof(ticket));
    return ok;
}

// Menjalankan server KDC untuk melayani permintaan kunci sesi dari Alice.
int main(int argc, char **argv)
{
    uint16_t port;
    uint8_t ka[16] = {0}, kb[16] = {0};
    SOCKET server = INVALID_SOCKET;
    int exit_code = 1;
    app_init();
    if (argc != 2 || !parse_port(argv[1], &port)) {
        fputs("Pemakaian: bin\\kdc.exe <port 1..65535>\n", stderr);
        return 1;
    }
    if (!net_init()) return 1;
    if (!read_master_key("Masukkan Ka untuk Alice", ka) ||
        !read_master_key("Masukkan Kb untuk Bob", kb)) goto done;
    server = listen_tcp(port);
    if (server == INVALID_SOCKET) goto done;
    printf("KDC siap di 0.0.0.0:%u. Ctrl+C untuk berhenti.\n", (unsigned)port);
    for (;;) {
        SOCKET client = accept(server, NULL, NULL);
        if (client == INVALID_SOCKET) {
            fprintf(stderr, "Accept KDC gagal (Winsock %d).\n", WSAGetLastError());
            break;
        }
        if (socket_timeouts(client, HANDSHAKE_TIMEOUT_MS))
            handle_request(client, ka, kb);
        close_connection(client);
        puts("KDC menunggu permintaan berikutnya.");
    }
done:
    close_connection(server);
    SecureZeroMemory(ka, sizeof(ka));
    SecureZeroMemory(kb, sizeof(kb));
    WSACleanup();
    return exit_code;
}
