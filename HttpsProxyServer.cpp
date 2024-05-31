#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <sstream>
#include <memory>

using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

void initialize_winsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed.\n";
        exit(EXIT_FAILURE);
    }
}

void cleanup_winsock() {
    WSACleanup();
}

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

using SSL_CTX_ptr = unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SSL_ptr = unique_ptr<SSL, decltype(&SSL_free)>;

SSL_CTX_ptr create_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return SSL_CTX_ptr(ctx, SSL_CTX_free);
}

void configure_context(SSL_CTX* ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "C:\\Users\\user\\source\\repos\\HttpsProxyServer\\server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "C:\\Users\\user\\source\\repos\\HttpsProxyServer\\server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

SOCKET create_socket(int port) {
    SOCKET sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        perror("Unable to bind");
        closesocket(sockfd);
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, SOMAXCONN) == SOCKET_ERROR) {
        perror("Unable to listen");
        closesocket(sockfd);
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

SOCKET connect_to_host(const string& hostname, int port) {
    struct addrinfo hints, * res;
    SOCKET sockfd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), to_string(port).c_str(), &hints, &res) != 0) {
        perror("getaddrinfo");
        return INVALID_SOCKET;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == INVALID_SOCKET) {
        perror("Unable to create socket");
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) == SOCKET_ERROR) {
        perror("Unable to connect to host");
        closesocket(sockfd);
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }

    freeaddrinfo(res);
    return sockfd;
}

void handle_http_request(SOCKET client_sock, const string& request) {
    istringstream iss(request);
    string method, url, version;
    iss >> method >> url >> version;

    // Extract the host and path from the URL
    size_t host_start = url.find("://") + 3;
    size_t path_start = url.find('/', host_start);
    string host = url.substr(host_start, path_start - host_start);
    string path = url.substr(path_start);

    SOCKET remote_sock = connect_to_host(host, 80);
    if (remote_sock == INVALID_SOCKET) {
        cerr << "Unable to connect to remote host.\n";
        return;
    }

    // Forward the initial request
    send(remote_sock, request.c_str(), request.length(), 0);

    // Forward responses from remote server to client
    char buffer[4096];
    int bytes;
    while ((bytes = recv(remote_sock, buffer, sizeof(buffer), 0)) > 0) {
        send(client_sock, buffer, bytes, 0);
    }

    closesocket(remote_sock);
}

void handle_https_request(SOCKET client_sock, SSL_CTX* ctx, const string& host, int port) {
    SOCKET remote_sock = connect_to_host(host, port);
    if (remote_sock == INVALID_SOCKET) {
        cerr << "Unable to connect to remote host.\n";
        return;
    }

    SSL_ptr ssl(SSL_new(ctx), SSL_free);
    SSL_set_fd(ssl.get(), client_sock);

    const char* response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(client_sock, response, strlen(response), 0);

    fd_set readfds;
    char buffer[4096];
    int bytes;

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(client_sock, &readfds);
        FD_SET(remote_sock, &readfds);

        int max_fd = max(client_sock, remote_sock) + 1;
        int activity = select(max_fd, &readfds, NULL, NULL, NULL);

        if (activity == SOCKET_ERROR) {
            perror("select");
            break;
        }

        if (FD_ISSET(client_sock, &readfds)) {
            if ((bytes = recv(client_sock, buffer, sizeof(buffer), 0)) <= 0) {
                break;
            }
            send(remote_sock, buffer, bytes, 0);
        }

        if (FD_ISSET(remote_sock, &readfds)) {
            if ((bytes = recv(remote_sock, buffer, sizeof(buffer), 0)) <= 0) {
                break;
            }
            send(client_sock, buffer, bytes, 0);
        }
    }

    SSL_shutdown(ssl.get());
}

void handle_client(SSL_CTX* ctx, SOCKET client_sock) {
    char buffer[4096];
    int bytes = recv(client_sock, buffer, sizeof(buffer), 0);
    if (bytes <= 0) {
        closesocket(client_sock);
        return;
    }

    buffer[bytes] = '\0';
    string request(buffer);

    if (request.substr(0, 7) == "CONNECT") {
        size_t pos = request.find(" ");
        size_t pos2 = request.find(" ", pos + 1);
        string host_port = request.substr(pos + 1, pos2 - pos - 1);
        size_t colon_pos = host_port.find(":");
        string host = host_port.substr(0, colon_pos);
        int port = stoi(host_port.substr(colon_pos + 1));
        handle_https_request(client_sock, ctx, host, port);
    }
    else {
        handle_http_request(client_sock, request);
    }

    closesocket(client_sock);
}

int main() {
    initialize_winsock();
    initialize_openssl();
    auto ctx = create_context();
    configure_context(ctx.get());

    int port = 8080;
    SOCKET server_fd = create_socket(port);

    vector<thread> threads;

    while (true) {
        SOCKET client_sock = accept(server_fd, NULL, NULL);
        if (client_sock == INVALID_SOCKET) {
            perror("Unable to accept connection");
            continue;
        }
        threads.emplace_back(thread(handle_client, ctx.get(), client_sock));
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    closesocket(server_fd);
    cleanup_openssl();
    cleanup_winsock();
    return 0;
}