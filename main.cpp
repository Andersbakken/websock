#include "WebSock.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/socket.h>

int main(int argc, char **argv)
{
    WebSocket::Options options;
    options.url = "wss://echo.websocket.org";
    for (int i = 1; i < argc; ++i) {
        options.url = argv[1];
    }
    options.connectTimeoutMS = 8000;
    std::string err;
    bool wss;

    uint16_t port;
    if (!strncmp(options.url.c_str(), "wss://", 6)) {
        wss = true;
        port = 443;
    } else if (!strncmp(options.url.c_str(), "ws://", 5)) {
        wss = false;
        port = 80;
    } else {
        fprintf(stderr, "Invalid url\n");
        return 1;
    }

    const size_t start = wss ? 3 : 2;
    const size_t colon = options.url.find(":", start + 3);
    size_t end = std::min(options.url.size(), options.url.find("/", start + 3));
    if (colon < end) {
        end = colon;
        port = atoi(options.url.c_str() + colon + 1);
    }
    options.hostname = options.url.substr(start + 3, end - start - 3);
    printf("hostname [%s]\n", options.hostname.c_str());

    hostent *host = gethostbyname(options.hostname.c_str());
    if (!host || !host->h_addr_list || !host->h_addr_list[0]) {
        fprintf(stderr, "Failed to look up host %s\n", options.hostname.c_str());
        return 1;
    }

    for (size_t i = 0; host->h_addr_list[i]; ++i) {
        printf("%s %d\n", inet_ntoa(*(struct in_addr *)(host->h_addr_list[i])), host->h_length);
    }
    memset(&options.sockaddr, 0, sizeof(sockaddr));
    if (host->h_length == 4) {
        // ipv4
        sockaddr_in &in = reinterpret_cast<sockaddr_in &>(options.sockaddr);
        memcpy(&in.sin_addr.s_addr, reinterpret_cast<struct in_addr *>(host->h_addr_list[0]), host->h_length);
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
    } else {
        fprintf(stderr, "ipv6 not implented yet\n");
        return 1;
    }
    options.sockaddr_len = host->h_length * 4;

    WebSocket websocket;
    if (!websocket.connect(options, &err)) {
        fprintf(stderr, "Failed to connect to %s - %s\n", options.url.c_str(), err.c_str());
        return 1;
    }

    while (websocket.state() != WebSocket::Error && websocket.state() != WebSocket::Closed) {
        fd_set r, w;
        FD_ZERO(&r);
        FD_ZERO(&w);
        unsigned long long timeout = 100000;
        int maxFd = 0;
        websocket.prepareSelect(maxFd, r, w, timeout);
        int ret;
        timeval t = { static_cast<time_t>(timeout / 1000), static_cast<suseconds_t>((timeout % 1000) * 1000 ) };
        printf("Calling select maxFd: %d, timeout: %llu\n",
               maxFd + 1, timeout);
        EINTRWRAP(ret, ::select(maxFd + 1, &r, &w, nullptr, &t));
        websocket.processSelect(ret, r, w);
        printf("state is %d\n", websocket.state());
    }

    // while (websocket
    return 0;
}
