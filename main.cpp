#include "WebSock.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <algorithm>
#include <string.h>
#include <unistd.h>
#include <string>
#include <sys/socket.h>
#include "truststore.cpp"

int main(int argc, char **argv)
{
    WebSocket::Options options;
    options.url = "wss://echo.websocket.org";
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--verbose") || !strcmp(argv[i], "-v")) {
            WebSocket::verbose = true;
        } else if (!strcmp(argv[i], "--truststore")) {
            if (i + 1 < argc) {
                FILE *f = fopen(argv[++i], "r");
                if (!f) {
                    fprintf(stderr, "Can't open %s for reading\n", argv[i]);
                    return 1;
                }
                fseek(f, 0, SEEK_END);
                const long size = ftell(f);
                options.truststore.resize(size);
                fseek(f, 0, SEEK_SET);
                if (fread(&options.truststore[0], 1, size, f) != size) {
                    fprintf(stderr, "Failed to read from %s\n", argv[i]);
                    fclose(f);
                    return 1;
                }
                fclose(f);
            } else {
                fprintf(stderr, "No argument for --truststore\n");
                return 1;
            }
        } else {
            options.url = argv[1];
        }
    }
    options.connectTimeoutMS = 8000;
    options.onMessage = [](WebSocket *, WebSocket::MessageEvent &&event) {
        printf("Got message event %s %d\n", event.text.empty() ? "binary" : "text", event.statusCode);
        if (event.text.empty()) {
            for (size_t i=0; i<event.binary.size(); ++i) {
                printf("0x%02x ", event.binary[i]);
                if (i && i % 16 == 0) {
                    printf("\n");
                }
            }
            printf("\n");
        } else {
            printf("%s\n", event.text.c_str());
        }
    };

    options.onClose = [](WebSocket *,WebSocket::CloseEvent &&event) {
        printf("GOT CLOSE EVENT %s %d %s\n", event.wasClean ? "clean" : "dirty",
               event.statusCode, event.reason.c_str());
    };
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
    std::transform(options.url.begin() + start + 3, options.url.begin() + end,
                   std::back_inserter(options.hostname),
                   [](unsigned char c) { return std::tolower(c); });

    // options.hostname = options.url.substr(start + 3, end - start - 3);
    if (options.truststore.empty())
        options.truststore = truststore;
    trace("hostname [%s]\n", options.hostname.c_str());

    hostent *host = gethostbyname(options.hostname.c_str());
    if (!host || !host->h_addr_list || !host->h_addr_list[0]) {
        fprintf(stderr, "Failed to look up host %s\n", options.hostname.c_str());
        return 1;
    }

    for (size_t i = 0; host->h_addr_list[i]; ++i) {
        trace("%s %d\n", inet_ntoa(*(struct in_addr *)(host->h_addr_list[i])), host->h_length);
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

    bool sent = false;
    while (websocket.state() != WebSocket::Error && websocket.state() != WebSocket::Closed) {
        fd_set r, w;
        FD_ZERO(&r);
        FD_ZERO(&w);
        unsigned long long timeout = sent ? std::numeric_limits<unsigned long long>::max() : 1000;
        int maxFd = 0;
        websocket.prepareSelect(maxFd, r, w, timeout);
        int ret;
        timeval t = { static_cast<time_t>(timeout / 1000), static_cast<suseconds_t>((timeout % 1000) * 1000 ) };
        trace("Calling select for %s maxFd: %d, timeout: %llu\n",
               WebSocket::stateToString(websocket.state()), maxFd + 1, timeout);
        EINTRWRAP(ret, ::select(maxFd + 1, &r, &w, nullptr,
                                timeout == std::numeric_limits<unsigned long long>::max() ? nullptr : &t));
        trace("Select for %s returned %d %d %s\n",
               WebSocket::stateToString(websocket.state()),
               ret, ret == -1 ? errno : 0, ret == -1 ? strerror(errno) : "");
        websocket.processSelect(ret, r, w);
        // trace("state is %d\n", websocket.state());
        if (!sent && !ret && websocket.state() == WebSocket::Connected) {
            websocket.send("Balls");
            printf("Sending balls\n");
            sent = true;
        }
    }

    // while (websocket
    return 0;
}
