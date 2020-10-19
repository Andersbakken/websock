#ifndef WEBSOCK_H
#define WEBSOCK_H

#include <openssl/ssl.h>
#include <string>
#include <sys/socket.h>
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
    State state() const { return mState; }

    void select(int &nfds, fd_set &r, fd_set &w, unsigned long long &timeout);
    void processSockets(int count, const fd_set &r, const fd_set &w);
private:
    static int sslCtxVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
    std::string mUrl, mCipherlist, mTruststore, mHostname;
    State mState { Unset };
    unsigned long long mConnectTimeout { std::numeric_limits<unsigned long long>::max() };
    time_t mCurrentTime { 0 };
    enum Flag {
        ConnectWantRead = 0x1,
        ConnectWantWrite = 0x2
    };
    unsigned int mFlags { 0 };
    int mFD { -1 };
    SSL_CTX *mSSLCtx { nullptr };
    SSL *mSSL { nullptr };
    int mPipe[2] { -1, -1 };
    bool mWss { false };
};

#endif /* WEBSOCK_H */
