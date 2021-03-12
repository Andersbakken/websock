#ifndef WEBSOCK_H
#define WEBSOCK_H

#include <functional>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/socket.h>

#include <openssl/ssl.h>
#include <wslay/wslay.h>

#define EINTRWRAP(ret, op)                      \
    do {                                        \
        ret = op;                               \
    } while (ret == -1 && errno == EINTR)

#if 0
#define trace(...) printf(__VA_ARGS__)
#else
#define trace(...)
#endif

class WebSocket
{
public:
    WebSocket();
    virtual ~WebSocket();

    struct MessageEvent {
        std::string text;
        std::vector<unsigned char> binary;
        uint16_t statusCode { 0 };
    };

    struct CloseEvent {
        uint16_t statusCode { 1005 };
        std::string reason;
        bool wasClean { true };
    };

    struct Options {
        std::string url, cipherlist, truststore, hostname;
        sockaddr_storage sockaddr;
        socklen_t sockaddr_len { 0 };
        unsigned long long connectTimeoutMS { 0 };
        time_t currentTime { 0 }; // for ssl
        std::unordered_map<std::string, std::string> headers;
        std::function<void(WebSocket *, MessageEvent &&message)> onMessage;
        std::function<void(WebSocket *, CloseEvent &&closeEvent)> onClose;
        std::function<void(WebSocket *, std::string &&error)> onError;
    };

    bool connect(const Options &conn, std::string *err);
    void send(const std::string &text);
    void send(const std::vector<unsigned char> &binary);
    bool close(uint16_t code = 1005, const std::string &reaason = std::string());
    void prepareSelect(int &nfds, fd_set &r, fd_set &w, unsigned long long &timeout);
    void processSelect(int count, const fd_set &r, const fd_set &w);
    void wakeup();

    enum State {
        Unset,
        TCPConnecting,
        SSLConnecting,
        WebSocketConnecting,
        WebSocketSentUpgrade,
        Connected,
        Closed,
        Error
    };

    static const char *stateToString(State state);
    State state() const { return mState; }
private:
    std::string createUpgradeRequest();
    void acceptUpgrade();
    void addToWriteBuffer(const void *data, size_t len);
    void writeSocketBuffer();
    int readData(void *buf, size_t bufSize);

    void createSSL();
    void sslConnect(int count, const fd_set &r, const fd_set &w);
    static int sslCtxVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
    static void sslCtxInfoCallback(const SSL *ssl, int where, int ret);

    void createWSContext();
    static ssize_t wsSend(wslay_event_context *ctx, const uint8_t *data, size_t len, int flags, void *user_data);
    static ssize_t wsRecv(wslay_event_context *ctx, uint8_t *data, size_t len, int flags, void *user_data);
    static void wsOnMessage(wslay_event_context *, const wslay_event_on_msg_recv_arg *arg, void *user_data);
    static int wsGenMask(wslay_event_context *ctx, uint8_t *buf, size_t len, void *user_data);

    static std::unordered_map<SSL *, WebSocket *> sSockets;
    State mState { Unset };
    bool mSSLWantsWrite { false };
    unsigned long long mConnectTimeout { std::numeric_limits<unsigned long long>::max() };
    Options mOptions;
    int mFD { -1 };
    SSL_CTX *mSSLCtx { nullptr };
    SSL *mSSL { nullptr };
    int mPipe[2] { -1, -1 };
    bool mWokenUp { false };
    wslay_event_context *mContext { nullptr };
    std::string mUpgradeKey, mUpgradeResponse;
    std::vector<unsigned char> mWriteBuffer, mRecvBuffer;
    bool mWss { false };
};

#endif /* WEBSOCK_H */
