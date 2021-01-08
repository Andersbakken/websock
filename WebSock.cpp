#include "WebSock.h"

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <algorithm>
#include <string.h>
#include <cctype>
#include <functional>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#if !defined(__GNUC__) || defined(__ANDROID__)
# define PRINTF_ATTR(x,y)
#else
# define PRINTF_ATTR(x,y) __attribute__ ((__format__ (__printf__, x, y)))
#endif

static std::string base64Encode(const unsigned char* in, size_t in_len);
static inline unsigned long long mono();
static std::string format(const char *fmt, ...) PRINTF_ATTR(1, 2);
static bool setNonblocking(int fd, std::string *err);

std::unordered_map<SSL *, WebSocket *> WebSocket::sSockets;
WebSocket::WebSocket()
{
}

WebSocket::~WebSocket()
{
    int ret;

    if (mSSL) {
        sSockets.erase(mSSL);
        SSL_free(mSSL);
    }

    if (mSSLCtx) {
        SSL_CTX_free(mSSLCtx);
    }

    if (mFD != -1) {
        EINTRWRAP(ret, ::close(mFD));
    }

    if (mPipe[0] != -1) {
        EINTRWRAP(ret, ::close(mPipe[0]));
        EINTRWRAP(ret, ::close(mPipe[1]));
    }
}

bool WebSocket::connect(const Options &options, std::string *err)
{
    if (!mOptions.url.empty()) {
        if (err)
            *err = "Already connecting";
        return false;
    }
    mOptions = options;

    mOptions.url.reserve(options.url.size());
    std::transform(options.url.begin(), options.url.end(), std::back_inserter(mOptions.url),
                   [](unsigned char c) { return std::tolower(c); });

    mFD = ::socket(options.sockaddr_len == sizeof(sockaddr_in) ? AF_INET : AF_INET6, SOCK_STREAM, 0);
    if (mFD == -1) {
        mState = Error;
        if (err)
            *err = "Failed to create socket";
        return false;
    }

    if (!setNonblocking(mFD, err)) {
        mState = Error;
        return false;
    }

    int ret;
    EINTRWRAP(ret, ::connect(mFD, reinterpret_cast<const struct sockaddr *>(&options.sockaddr), options.sockaddr_len));
    printf("connect returned %d -> %d %s\n", ret, errno, strerror(errno));
    if (ret == -1) {
        if (errno == EINPROGRESS) {
            mState = TCPConnecting;
        } else {
            mState = Error;
            if (err)
                *err = format("Failed to connect %d", errno);
            return false;
        }
    } else {
        printf("TCP Connected!\n");
        mState = mWss ? SSLConnecting : WebSocketConnecting;
    }

    ret = pipe(mPipe);
    if (ret != 0) {
        mState = Error;
        if (err)
            *err = format("Failed create pipe(2) %d", errno);
        return false;
    }

    if (!setNonblocking(mPipe[0], err) || !setNonblocking(mPipe[1], err)) {
        return false;
    }

    mWss = !strncmp(mOptions.url.c_str(), "wss://", 6);
    if (options.connectTimeoutMS != 0)
        mConnectTimeout = mono() + options.connectTimeoutMS;
    return true;
}

void WebSocket::prepareSelect(int &nfds, fd_set &r, fd_set &w, unsigned long long &timeout)
{
    printf("prepareSelect %s\n", stateToString(mState));
    switch (mState) {
    case Unset:
    case Error:
    case Closed:
        return;
    case TCPConnecting:
        FD_SET(mFD, &w);
        if (mConnectTimeout != std::numeric_limits<unsigned long long>::max()) {
            timeout = std::min(timeout, mConnectTimeout - mono());
        }
        break;
    case SSLConnecting:
        FD_SET(mFD, &r);
        if (mFlags & ConnectWantWrite) {
            FD_SET(mFD, &w);
        }
        break;
    case WebSocketConnecting:
        FD_SET(mFD, &r);
        break;
    case Connected:
        FD_SET(mFD, &r);
        if (!mWSContext) {
            createWSContext();
        }

        break;
    }
    if (mWriteBuffer) {
        FD_SET(mFD, &w);
    }
    nfds = std::max(nfds, mFD);
}

void WebSocket::processSelect(int count, const fd_set &r, const fd_set &w)
{
    mWokenUp = false;
    printf("processSelect %s %d - %d %d - %d\n", stateToString(mState),
           count, FD_ISSET(mFD, &r), FD_ISSET(mFD, &r), FD_ISSET(mPipe[0], &r));

    if (FD_ISSET(mPipe[0], &r)) {
        char buf;
        int r;
        EINTRWRAP(r, ::read(mPipe[0], &buf, 1));
    }
    switch (mState) {
    case Unset:
    case Error:
    case Closed:
        return;
    case TCPConnecting: {
        if (count && FD_ISSET(mFD, &w)) {
            int ret;
            int value;
            socklen_t size = sizeof(value);
            ret = getsockopt(mFD, SOL_SOCKET, SO_ERROR, &value, &size);
            if (ret == -1) {
                fprintf(stderr, "Failed to connect (getsockopt) to host %d\n", errno);
                mState = Error;
                return;
            }

            switch (value) {
            case EINPROGRESS:
                break;
            case EISCONN:
            case 0:
                printf("TCP CONNECTED!\n");
                if (mWss) {
                    mState = SSLConnecting;
                } else {
                    mState = WebSocketConnecting;
                }
                processSelect(count, r, w);
                break;
            default:
                fprintf(stderr, "Failed to connect to host %d\n", value);
                mState = Error;
                return;
            }
        } else if (mConnectTimeout != std::numeric_limits<unsigned long long>::max()) {
            fprintf(stderr, "Timed out connecting to host\n");
            mState = Error;
        }
        break; }
    case SSLConnecting:
        if (!mSSLCtx) {
            createSSL();
        }
        sslConnect(count, r, w);
        break;
    case WebSocketConnecting: {
        const bool wasEmpty = mUpgradeKey.empty();
        if (mUpgradeKey.empty()) {
            std::string req = createUpgradeRequest();
            assert(!mUpgradeKey.empty());
            write(req.c_str(), req.size());
        }

        if ((wasEmpty || FD_ISSET(mFD, &w)) && mWriteBuffer) {
            writeSocketBuffer();
        }
        break; }
    case Connected:
        break;
    }
}

void WebSocket::wakeup()
{
    assert(mPipe[0] != -1);
    if (!mWokenUp) {
        mWokenUp = true;
        int ret;
        EINTRWRAP(ret, ::write(mPipe[1], "w", 1));
    }
}

int WebSocket::sslCtxVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    return preverify_ok;
}


void WebSocket::write(const void *data, size_t len)
{
    assert(len);
    mWriteBuffer = reinterpret_cast<unsigned char *>(realloc(mWriteBuffer, mWriteBufferSize + len));
    memcpy(mWriteBuffer + mWriteBufferSize, data, len);
    mWriteBufferSize += len;
    wakeup();
}

void WebSocket::writeSocketBuffer()
{
    printf("writeSocketBuffer %zu\n", mWriteBufferSize);
    size_t written = 0;
    do {
        int w;
        assert(mWriteBufferSize > written);
        EINTRWRAP(w, ::write(mFD, mWriteBuffer + written, mWriteBufferSize - written));
        if (w == -1) {
            if (errno != EWOULDBLOCK && errno != EAGAIN) {
                printf("Got an error writing: %d %s\n",
                       errno, strerror(errno));
            }
            break;
        } else {
            assert(w > 0);
            written += w;
        }
    } while (written < mWriteBufferSize);
    if (written == mWriteBufferSize) {
        free(mWriteBuffer);
        mWriteBuffer = nullptr;
        mWriteBufferSize = 0;
    } else if (written) {
        const size_t remaining = mWriteBufferSize - written;
        memmove(mWriteBuffer + written, mWriteBuffer, remaining);
        mWriteBuffer = reinterpret_cast<unsigned char *>(realloc(mWriteBuffer, remaining));
        mWriteBufferSize = remaining;
    }
}

void WebSocket::createSSL()
{
    assert(!mSSLCtx);
    mSSLCtx = SSL_CTX_new(TLS_client_method());
    if (!mSSLCtx) {
        fprintf(stderr, "Failed to create SSL_CTX\n");
        mState = Error;
        return;
    }
    // ### error checking for all of these
    SSL_CTX_set_min_proto_version(mSSLCtx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(mSSLCtx, TLS1_3_VERSION);
    SSL_CTX_set_options(mSSLCtx, SSL_OP_ALL | SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(mSSLCtx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (!mOptions.cipherlist.empty()) {
        SSL_CTX_set_cipher_list(mSSLCtx, mOptions.cipherlist.c_str());
    }

    if (!mOptions.truststore.empty()) {
        X509_STORE *store = SSL_CTX_get_cert_store(mSSLCtx);
        assert(store);
        BIO *b = BIO_new_mem_buf(mOptions.truststore.c_str(), mOptions.truststore.size());
        assert(b);
        while (true) {
            X509 *x509 = PEM_read_bio_X509(b, 0, 0, 0);
            if (!x509)
                break;
            X509_STORE_add_cert(store, x509);
        }
        BIO_free(b);
    }

    SSL_CTX_set_verify(mSSLCtx, SSL_VERIFY_PEER, sslCtxVerifyCallback);
    SSL_CTX_set_info_callback(mSSLCtx, sslCtxInfoCallback);
    assert(!mSSL);
    mSSL = SSL_new(mSSLCtx);
    if (!mSSL) {
        fprintf(stderr, "Failed to create SSL\n");
        mState = Error;
        return;
    }

    if (mOptions.currentTime) {
        X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set_time(param, mOptions.currentTime);
        SSL_set1_param(mSSL, param);
        X509_VERIFY_PARAM_free(param);
    }
    SSL_set_connect_state(mSSL);
    SSL_set_tlsext_host_name(mSSL, mOptions.hostname.c_str());

    BIO *bio = BIO_new_socket(mFD, false);
    assert(bio);
    SSL_set_bio(mSSL, bio, bio);
    sSockets[mSSL] = this;
}

void WebSocket::sslConnect(int count, const fd_set &r, const fd_set &w)
{
    printf("HERE 0x%x - %d %d\n", mFlags, FD_ISSET(mFD, &r), FD_ISSET(mFD, &w));

    if (FD_ISSET(mFD, &r) || FD_ISSET(mFD, &w)) {
        ERR_clear_error();
        mFlags &= ~(ConnectWantWrite|ConnectWantRead);
        const int connect = SSL_connect(mSSL);
        printf("CALLED CONNECT %d\n", connect);
        if (connect <= 0) {
            const int sslErr = SSL_get_error(mSSL, connect);
            switch (sslErr) {
            case SSL_ERROR_NONE:
                printf("[WebSock.cpp:%d]: case SSL_ERROR_NONE:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_ZERO_RETURN:
                printf("[WebSock.cpp:%d]: case SSL_ERROR_ZERO_RETURN:\n", __LINE__); fflush(stdout);
                mState = Closed;
                break;
            case SSL_ERROR_WANT_READ:
                mFlags |= ConnectWantRead;
                printf("[WebSock.cpp:%d]: case SSL_ERROR_WANT_READ:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_WANT_WRITE:
                mFlags |= ConnectWantWrite;
                printf("[WebSock.cpp:%d]: case SSL_ERROR_WANT_WRITE:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_WANT_CONNECT:
                printf("[WebSock.cpp:%d]: case SSL_ERROR_WANT_CONNECT:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_WANT_ACCEPT:
                printf("[WebSock.cpp:%d]: case SSL_ERROR_WANT_ACCEPT:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_WANT_ASYNC_JOB:
                printf("[WebSock.cpp:%d]: case SSL_ERROR_WANT_ASYNC_JOB:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
                printf("[WebSock.cpp:%d]: case SSL_ERROR_WANT_CLIENT_HELLO_CB:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_SYSCALL:
                printf("[WebSock.cpp:%d]: case SSL_ERROR_SYSCALL:\n", __LINE__); fflush(stdout);
                mState = Error;
                break;
            case SSL_ERROR_SSL:
                printf("[WebSock.cpp:%d]: case SSL_ERROR_SSL:\n", __LINE__); fflush(stdout);
                mState = Error;
                break;
            default:
                break;
            }

            printf("GOT SSL ERR %d\n", sslErr);
        } else {
            assert(connect == 1);
            mState = WebSocketConnecting;
            processSelect(count, r, w);
        }
    }
}

const char *WebSocket::stateToString(State state)
{
    switch (state) {
    case Unset: return "Unset";
    case TCPConnecting: return "TCPConnecting";
    case SSLConnecting: return "SSLConnecting";
    case WebSocketConnecting: return "WebSocketConnecting";
    case Connected: return "Connected";
    case Closed: return "Closed";
    case Error: return "Error";
    }
    return "";
}

void WebSocket::sslCtxInfoCallback(const SSL *ssl, int where, int ret)
{
    WebSocket *sock = sSockets[const_cast<SSL *>(ssl)];
    assert(sock);
    const char *str;

    if (where & SSL_ST_CONNECT) {
        str = "SSL_connect";
    } else if (where & SSL_ST_ACCEPT) {
        str = "SSL_accept";
    } else {
        str = "undefined";
    }

    if (where & SSL_CB_HANDSHAKE_DONE) {
        printf("[WEBSOCK SSL] - %s: handshake done session %sreused\n", sock->mOptions.url.c_str(),
               SSL_session_reused(const_cast<SSL *>(ssl)) ? "" : "not ");
        // data->metrics.setSSLMode(SSL_session_reused(const_cast<SSL *>(ssl)) ? NetworkMetrics::SSLResumed : NetworkMetrics::SSL);
    }

    if (where & SSL_CB_LOOP) {
        printf("[WEBSOCK SSL] - %s: %s:%s\n", sock->mOptions.url.c_str(), str, SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
        printf("[WEBSOCK SSL] - %s: SSL3 alert %s:%s:%s\n", sock->mOptions.url.c_str(),
               str, SSL_alert_type_string_long(ret),
               SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT && ret <= 0) {
        printf("[WEBSOCK SSL] - %s: %s:%s in %s\n", sock->mOptions.url.c_str(), str, ret ? "error" : "failed",
               SSL_state_string_long(ssl));
    }
}

std::string WebSocket::createUpgradeRequest()
{
    unsigned char buf[16];
    RAND_bytes(buf, sizeof(buf));
    assert(mUpgradeKey.empty());
    mUpgradeKey = base64Encode(buf, sizeof(buf));
    const size_t pathIdx = mOptions.url.find('/', 6);
    std::string req = format("GET %s HTTP/1.1\r\n"
                             "Host: %s\r\n"
                             "Upgrade: websocket\r\n"
                             "Connection: Upgrade\r\n"
                             "Pragma: no-cache\r\n"
                             "Cache-Control: no-cache\r\n"
                             "Sec-WebSocket-Key: %s\r\n"
                             "Sec-WebSocket-Version: 13\r\n",
                             pathIdx == std::string::npos ? "/" : mOptions.url.c_str() + pathIdx,
                             mOptions.hostname.c_str(),
                             mUpgradeKey.c_str());

    for (const auto &ref : mOptions.headers) {
        req += ref.first + ": " + ref.second + "\r\n";
    }
    req += "\r\n";
    return req;
}

// ----------------------

static std::string base64Encode(const unsigned char* in, size_t in_len)
{
    BIO *buff, *b64f;
    BUF_MEM *ptr;

    b64f = BIO_new(BIO_f_base64());
    buff = BIO_new(BIO_s_mem());
    buff = BIO_push(b64f, buff);

    BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(buff, BIO_CLOSE);
    BIO_write(buff, in, in_len);
    BIO_flush(buff);

    BIO_get_mem_ptr(buff, &ptr);
    const size_t outLen = ptr->length;
    std::string ret(ptr->data, outLen);
    BIO_free_all(buff);
    return ret;
}

static inline unsigned long long mono()
{
    timespec ts;
#if defined(__APPLE__)
    static double sTimebase = 0.0;
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, []() -> void {
        mach_timebase_info_data_t tb;
        mach_timebase_info(&tb);
        sTimebase = tb.numer;
        sTimebase /= tb.denom;
    });
    const double time = mach_absolute_time() * sTimebase;
    ts.tv_sec = time * +1.0E-9;
    ts.tv_nsec = time - (ts->tv_sec * static_cast<uint64_t>(1000000000));
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (static_cast<unsigned long long>(ts.tv_sec) * 1000ull) + (static_cast<unsigned long long>(ts.tv_nsec) / 1000000ull);
}

static std::string format(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    char buf[4096];
    buf[sizeof(buf) - 1] = '\0';
    const int w = vsnprintf(buf, sizeof(buf) - 1, fmt, va);
    va_end(va);
    if (w >= sizeof(buf) - 1) {
        return buf;
    }
    return std::string(buf, w);
}

static bool setNonblocking(int fd, std::string *err)
{
    int ret;
    EINTRWRAP(ret, ::fcntl(fd, F_GETFL));
    if (ret == -1) {
        if (err)
            *err = format("Failed to set %d to non blocking %d (F_GETFL)", fd, errno);
        return false;
    }

    const int flags = ret | O_NONBLOCK;
    EINTRWRAP(ret, ::fcntl(fd, F_SETFL, flags));
    if (ret == -1) {
        if (err)
            *err = format("Failed to set %d to non blocking %d (F_SETFL)", fd, errno);
        return false;
    }

    return true;
}

void WebSocket::createWSContext()
{
    assert(!mWSContext);
    wslay_event_callbacks callbacks = { wsRecv, wsSend, wsGenMask, nullptr, nullptr, nullptr, wsOnMessage };
    wslay_event_context *context = nullptr;
    const int err = wslay_event_context_client_init(&context, &callbacks, this);
    assert(err);
}

ssize_t WebSocket::wsSend(wslay_event_context *ctx, const uint8_t *data, size_t len, int flags, void *user_data)
{
}

ssize_t WebSocket::wsRecv(wslay_event_context *ctx, uint8_t *data, size_t len, int flags, void *user_data)
{
}

void WebSocket::wsOnMessage(wslay_event_context *, const wslay_event_on_msg_recv_arg *arg, void *user_data)
{
}

int WebSocket::wsGenMask(wslay_event_context *ctx, uint8_t *buf, size_t len, void *user_data)
{
}

