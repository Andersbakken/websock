#ifndef WEBSOCK_H
#define WEBSOCK_H

#include <openssl/ssl.h>
#include <string>
#include <sys/socket.h>
#include <unordered_map>
#include <wslay/wslay.h>
#include <limits>

#define EINTRWRAP(ret, op)                      \
    do {                                        \
        ret = op;                               \
    } while (ret == -1 && errno == EINTR)

class WebSocket
{
public:
    WebSocket();
    virtual ~WebSocket();
    struct Options {
        std::string url, cipherlist, truststore, hostname;
        sockaddr_storage sockaddr;
        socklen_t sockaddr_len { 0 };
        unsigned long long connectTimeoutMS { 0 };
        time_t currentTime { 0 };
        std::unordered_map<std::string, std::string> headers;
    };
    bool connect(const Options &conn, std::string *err);

    enum State {
        Unset,
        TCPConnecting,
        SSLConnecting,
        WebSocketConnecting,
        Connected,
        Closed,
        Error
    };
    static const char *stateToString(State state);
    State state() const { return mState; }

    void prepareSelect(int &nfds, fd_set &r, fd_set &w, unsigned long long &timeout);
    void processSelect(int count, const fd_set &r, const fd_set &w);
    void wakeup();
private:
    std::string createUpgradeRequest();
    void addToWriteBuffer(const void *data, size_t len);
    void writeSocketBuffer();
    void acceptUpgrade();
    void createSSL();
    void sslConnect(int count, const fd_set &r, const fd_set &w);
    void createWSContext();
    static int sslCtxVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
    static void sslCtxInfoCallback(const SSL *ssl, int where, int ret);

    static ssize_t wsSend(wslay_event_context *ctx, const uint8_t *data, size_t len, int flags, void *user_data);
    static ssize_t wsRecv(wslay_event_context *ctx, uint8_t *data, size_t len, int flags, void *user_data);
    static void wsOnMessage(wslay_event_context *, const wslay_event_on_msg_recv_arg *arg, void *user_data);
    static int wsGenMask(wslay_event_context *ctx, uint8_t *buf, size_t len, void *user_data);

    static std::unordered_map<SSL *, WebSocket *> sSockets;
    State mState { Unset };
    enum Flag {
        ConnectWantRead = 0x1,
        ConnectWantWrite = 0x2
    };
    unsigned int mFlags { 0 };
    unsigned long long mConnectTimeout { std::numeric_limits<unsigned long long>::max() };
    Options mOptions;
    int mFD { -1 };
    SSL_CTX *mSSLCtx { nullptr };
    SSL *mSSL { nullptr };
    int mPipe[2] { -1, -1 };
    bool mWokenUp { false };
    wslay_event_context *mWSContext { nullptr };
    std::string mUpgradeKey, mUpgradeResponse;
    unsigned char *mWriteBuffer { nullptr };
    size_t mWriteBufferSize { 0 };
    bool mWss { false };
};

#endif /* WEBSOCK_H */
