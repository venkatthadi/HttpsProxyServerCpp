#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <openssl/rand.h>

using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

void initialize_winsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        cerr << "WSAStartup failed: " << result << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Winsock initialized" << endl;
}

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    cout << "OpenSSL initialized" << endl;
}

void cleanup_openssl() {
    EVP_cleanup();
    cout << "OpenSSL cleaned up" << endl;
}

SSL_CTX* create_server_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        cerr << "Unable to create SSL context" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    cout << "Server context created" << endl;

    return ctx;
}

SSL_CTX* create_client_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        cerr << "Unable to create SSL context" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    cout << "Server context created" << endl;

    return ctx;
}

EVP_PKEY* generate_private_key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) {
        cerr << "EVP_PKEY_CTX_new_id failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        cerr << "EVP_PKEY_keygen_init failed" << endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
        cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits failed" << endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        cerr << "EVP_PKEY_keygen failed" << endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

void configure_context(SSL_CTX* ctx, X509* cert, EVP_PKEY* pkey) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        cerr << "Error using certificate" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    cout << "Certificate used" << endl;

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        cerr << "Error using private key" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    cout << "Private key used" << endl;
}

ASN1_INTEGER* generate_serial() {
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    if (!serial) {
        cerr << "ASN1_INTEGER_new failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Generate a random 64-bit integer for the serial number
    uint64_t serial_number = 0;
    if (!RAND_bytes((unsigned char*)&serial_number, sizeof(serial_number))) {
        cerr << "RAND_bytes failed" << endl;
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        exit(EXIT_FAILURE);
    }

    // Convert the random number to ASN1_INTEGER
    if (!ASN1_INTEGER_set_uint64(serial, serial_number)) {
        cerr << "ASN1_INTEGER_set_uint64 failed" << endl;
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        exit(EXIT_FAILURE);
    }

    return serial;
}

vector<string> get_sans(X509* cert) {
    vector<string> sans;
    STACK_OF(GENERAL_NAME)* names = NULL;

    names = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (names == NULL) {
        return sans;
    }

    int num_names = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < num_names; i++) {
        GENERAL_NAME* gen_name = sk_GENERAL_NAME_value(names, i);
        if (gen_name->type == GEN_DNS) {
            char* dns_name = (char*)ASN1_STRING_get0_data(gen_name->d.dNSName);
            sans.push_back(string(dns_name));
        }
    }
    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    return sans;
}

// Function to extract CN from the target certificate
string get_cn(X509* cert) {
    X509_NAME* subj = X509_get_subject_name(cert);
    char cn[256];
    X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
    return string(cn);
}

X509* create_certificate(X509* ca_cert, EVP_PKEY* ca_pkey, EVP_PKEY* pkey, X509* target_cert) {
    X509* cert = X509_new();
    if (!cert) {
        cerr << "X509_new failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    X509_set_version(cert, 2);

    ASN1_INTEGER* serial = generate_serial();
    X509_set_serialNumber(cert, serial);
    cout << "Serial assigned" << endl;
    ASN1_INTEGER_free(serial);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);  // 1 year validity

    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Proxy Inc.", -1, -1, 0);

    // Extract CN and SANs from target certificate
    string cn = get_cn(target_cert);
    vector<string> sans = get_sans(target_cert);

    // Set CN
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // Add SANs
    if (!sans.empty()) {
        STACK_OF(GENERAL_NAME)* san_list = sk_GENERAL_NAME_new_null();
        for (const string& san : sans) {
            GENERAL_NAME* gen_name = GENERAL_NAME_new();
            ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
            ASN1_STRING_set(ia5, san.c_str(), san.size());
            gen_name->d.dNSName = ia5;
            gen_name->type = GEN_DNS;
            sk_GENERAL_NAME_push(san_list, gen_name);
        }

        X509_EXTENSION* ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, san_list);
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
        sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
    }

    if (!X509_sign(cert, ca_pkey, EVP_sha256())) {
        cerr << "Error signing certificate" << endl;
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        exit(EXIT_FAILURE);
    }

    return cert;
}

SOCKET create_socket(int port) {
    SOCKET s;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        cerr << "Unable to create socket: " << WSAGetLastError() << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Socket created" << endl;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        cerr << "Unable to bind: " << WSAGetLastError() << endl;
        closesocket(s);
        exit(EXIT_FAILURE);
    }
    cout << "Socket bound to port " << port << endl;

    if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "Unable to listen: " << WSAGetLastError() << endl;
        closesocket(s);
        exit(EXIT_FAILURE);
    }
    cout << "Listening on port " << port << endl;

    return s;
}

SOCKET connect_to_target(const string& hostname, int port) {
    SOCKET sock;
    struct addrinfo hints, * res, * p;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), port_str, &hints, &res) != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }
    cout << "Resolved hostname: " << hostname << endl;

    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        if (connect(sock, p->ai_addr, p->ai_addrlen) == SOCKET_ERROR) {
            closesocket(sock);
            continue;
        }

        break;
    }

    if (p == NULL) {
        cerr << "Unable to connect to target server: " << hostname << endl;
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }
    cout << "Connected to target server: " << hostname << endl;

    freeaddrinfo(res);
    return sock;
}

bool parse_connect_request(const string& request, string& hostname, int& port) {
    string connect_method = "CONNECT ";
    size_t start_pos = request.find(connect_method);
    if (start_pos == string::npos) {
        return false;
    }
    start_pos += connect_method.length();
    size_t end_pos = request.find(" ", start_pos);
    if (end_pos == string::npos) {
        return false;
    }
    string host_port = request.substr(start_pos, end_pos - start_pos);
    size_t colon_pos = host_port.find(":");
    if (colon_pos == string::npos) {
        return false;
    }
    hostname = host_port.substr(0, colon_pos);
    port = stoi(host_port.substr(colon_pos + 1));
    return true;
}

string extract_host(const string& request) {
    string host_header = "Host: ";
    size_t start_pos = request.find(host_header);
    if (start_pos == string::npos) {
        return "";
    }
    start_pos += host_header.length();
    size_t end_pos = request.find("\r\n", start_pos);
    if (end_pos == string::npos) {
        return "";
    }
    return request.substr(start_pos, end_pos - start_pos);
}

void forward_data(SSL* source_ssl, SSL* dest_ssl) {
    const int buffer_size = 4096;
    char buffer[buffer_size];
    int bytes;

    while ((bytes = SSL_read(source_ssl, buffer, buffer_size)) > 0) {
        SSL_write(dest_ssl, buffer, bytes);
    }
}

void handle_client(SOCKET client_sock, SSL_CTX* ssl_ctx, X509* ca_cert, EVP_PKEY* ca_pkey) {
    char buffer[4096];
    int bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        cerr << "Failed to read CONNECT request from client" << endl;
        closesocket(client_sock);
        return;
    }
    buffer[bytes] = '\0';
    string request(buffer);

    string hostname;
    int port;
    if (!parse_connect_request(request, hostname, port)) {
        cerr << "Failed to parse CONNECT request" << endl;
        closesocket(client_sock);
        return;
    }
    cout << "Parsed CONNECT request: " << hostname << ":" << port << endl;

    const char* response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(client_sock, response, strlen(response), 0);
    cout << "Proxy established connection with client." << endl;

    // Create SSL context for the target connection
    SSL_CTX* dynamic_ctx = create_client_context();

    SOCKET target_sock = connect_to_target(hostname, port);
    SSL* target_ssl = SSL_new(dynamic_ctx);
    SSL_set_fd(target_ssl, target_sock);

    if (SSL_connect(target_ssl) <= 0) {
        cerr << "SSL connection to target server failed" << endl;
        ERR_print_errors_fp(stderr);
        closesocket(target_sock);
        SSL_free(target_ssl);
        closesocket(client_sock);
        return;
    }
    cout << "SSL connection to target server established" << endl;

    // Get the target server's certificate
    X509* target_cert = SSL_get_peer_certificate(target_ssl);
    if (!target_cert) {
        cerr << "No certificate from target server" << endl;
        SSL_shutdown(target_ssl);
        SSL_free(target_ssl);
        closesocket(target_sock);
        closesocket(client_sock);
        return;
    }

    // Create a new SSL context for the client connection with dynamic ciphers
    SSL_CTX* client_ctx = create_server_context();

    // Generate a new private key and certificate for the client, including SANs and CN from target
    EVP_PKEY* pkey = generate_private_key();
    X509* cert = create_certificate(ca_cert, ca_pkey, pkey, target_cert);
    configure_context(client_ctx, cert, pkey);

    // Create SSL object for the client connection
    SSL* client_ssl = SSL_new(client_ctx);
    SSL_set_fd(client_ssl, client_sock);

    if (SSL_accept(client_ssl) <= 0) {
        cerr << "SSL handshake with client failed" << endl;
        ERR_print_errors_fp(stderr);
        SSL_free(client_ssl);
        SSL_CTX_free(client_ctx);
        closesocket(client_sock);
        SSL_shutdown(target_ssl);
        SSL_free(target_ssl);
        closesocket(target_sock);
        return;
    }
    cout << "SSL handshake with client successful" << endl;

    // Forward data between client and target
    thread client_to_target(forward_data, client_ssl, target_ssl);
    thread target_to_client(forward_data, target_ssl, client_ssl);

    client_to_target.join();
    target_to_client.join();

    SSL_shutdown(target_ssl);
    SSL_free(target_ssl);
    closesocket(target_sock);

    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    closesocket(client_sock);

    SSL_CTX_free(client_ctx);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    X509_free(target_cert);

    cout << "Connection to target server closed" << endl;
}

int main() {
    int port = 8080;

    initialize_winsock();
    initialize_openssl();

    SSL_CTX* ssl_ctx = create_server_context();

    FILE* ca_cert_file = fopen("C:\\Users\\user\\OneDrive\\Desktop\\Certs\\rootCA.crt", "r");
    if (!ca_cert_file) {
        cerr << "Error opening CA certificate file" << endl;
        exit(EXIT_FAILURE);
    }
    X509* ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);
    if (!ca_cert) {
        cerr << "Error reading CA certificate" << endl;
        exit(EXIT_FAILURE);
    }

    FILE* ca_pkey_file = fopen("C:\\Users\\user\\OneDrive\\Desktop\\Certs\\rootCA.key", "r");
    if (!ca_pkey_file) {
        cerr << "Error opening CA private key file" << endl;
        exit(EXIT_FAILURE);
    }
    EVP_PKEY* ca_pkey = PEM_read_PrivateKey(ca_pkey_file, NULL, NULL, NULL);
    fclose(ca_pkey_file);
    if (!ca_pkey) {
        cerr << "Error reading CA private key" << endl;
        exit(EXIT_FAILURE);
    }

    SOCKET server_sock = create_socket(port);

    while (true) {
        struct sockaddr_in addr;
        int addr_len = sizeof(addr);
        SOCKET client_sock = accept(server_sock, (struct sockaddr*)&addr, &addr_len);
        if (client_sock == INVALID_SOCKET) {
            cerr << "Unable to accept client: " << WSAGetLastError() << endl;
            continue;
        }
        cout << "Client accepted" << endl;

        thread(handle_client, client_sock, ssl_ctx, ca_cert, ca_pkey).detach();
    }

    closesocket(server_sock);
    SSL_CTX_free(ssl_ctx);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_pkey);
    cleanup_openssl();
    WSACleanup();

    return 0;
}