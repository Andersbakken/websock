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

#if !defined(__GNUC__) || defined(__ANDROID__)
# define PRINTF_ATTR(x,y)
#else
# define PRINTF_ATTR(x,y) __attribute__ ((__format__ (__printf__, x, y)))
#endif

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

static std::string format(const char *fmt, ...) PRINTF_ATTR(1, 2);
std::string format(const char *fmt, ...)
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

WebSocket::WebSocket()
{
}

WebSocket::~WebSocket()
{
    int ret;

    if (mSSL) {
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

int fuck(int a)
{
    return a;
}

bool WebSocket::connect(const Options &options, std::string *err)
{
    if (!mUrl.empty()) {
        if (err)
            *err = "Already connecting";
        return false;
    }

    mUrl.reserve(options.url.size());
    std::transform(options.url.begin(), options.url.end(), std::back_inserter(mUrl),
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

    mWss = !strncmp(mUrl.c_str(), "wss://", 6);
    if (options.connectTimeoutMS != 0)
        mConnectTimeout = mono() + options.connectTimeoutMS;
    mCurrentTime = options.currentTime;
    mTruststore = options.truststore;
    mCipherlist = options.cipherlist;
    mHostname = options.hostname;
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
        nfds = std::max(nfds, mFD);
        if (mConnectTimeout != std::numeric_limits<unsigned long long>::max()) {
            timeout = std::min(timeout, mConnectTimeout - mono());
        }
        break;
    case SSLConnecting:
        FD_SET(mFD, &r);
        nfds = std::max(nfds, mFD);
        if (mFlags & ConnectWantWrite) {
            FD_SET(mFD, &w);
        }
        break;
    case WebSocketConnecting:
        break;
    case Connected:
        FD_SET(mPipe[0], &r);
        nfds = std::max(nfds, mPipe[0]);
        break;
    }
}

void WebSocket::processSelect(int count, const fd_set &r, const fd_set &w)
{
    printf("processSelect %s %d - %d %d - %d\n", stateToString(mState),
           count, FD_ISSET(mFD, &r), FD_ISSET(mFD, &r), FD_ISSET(mPipe[0], &r));
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
        break;
    case WebSocketConnecting:
        break;
    case Connected:
        break;
    }
}

int WebSocket::sslCtxVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    return preverify_ok;
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
    if (!mCipherlist.empty()) {
        SSL_CTX_set_cipher_list(mSSLCtx, mCipherlist.c_str());
    }

    if (!mTruststore.empty()) {
        X509_STORE *store = SSL_CTX_get_cert_store(mSSLCtx);
        assert(store);
        BIO *b = BIO_new_mem_buf(mTruststore.c_str(), mTruststore.size());
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

    if (mCurrentTime) {
        X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set_time(param, mCurrentTime);
        SSL_set1_param(mSSL, param);
        X509_VERIFY_PARAM_free(param);
    }
    SSL_set_connect_state(mSSL);
    SSL_set_tlsext_host_name(mSSL, mHostname.c_str());

    BIO *bio = BIO_new_socket(mFD, false);
    assert(bio);
    SSL_set_bio(mSSL, bio, bio);

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
    // SSL_CTX *sslInitialCtx = SSL_get_SSL_CTX(ssl);
    const char *str;

    if (where & SSL_ST_CONNECT) {
        str = "SSL_connect";
    } else if (where & SSL_ST_ACCEPT) {
        str = "SSL_accept";
    } else {
        str = "undefined";
    }

    if (where & SSL_CB_HANDSHAKE_DONE) {
        printf("[WEBSOCK SSL] - %s: handshake done session %sreused\n", "", // data->resource->url(),
               SSL_session_reused(const_cast<SSL *>(ssl)) ? "" : "not ");
        // data->metrics.setSSLMode(SSL_session_reused(const_cast<SSL *>(ssl)) ? NetworkMetrics::SSLResumed : NetworkMetrics::SSL);
    }

    if (where & SSL_CB_LOOP) {
        printf("[WEBSOCK SSL] - %s: %s:%s\n", "", str, SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
        printf("[WEBSOCK SSL] - %s: SSL3 alert %s:%s:%s\n", "",
               str, SSL_alert_type_string_long(ret),
               SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT && ret <= 0) {
        printf("[WEBSOCK SSL] - %s: %s:%s in %s\n", "", str, ret ? "error" : "failed",
               SSL_state_string_long(ssl));
    }
}
