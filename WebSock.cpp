#include "WebSock.h"

#include <algorithm>
#include <assert.h>
#include <cctype>
#include <fcntl.h>
#include <functional>
#include <netinet/in.h>
#include <memory>
#include <netinet/ip.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#if !defined(__GNUC__) || defined(__ANDROID__)
# define PRINTF_ATTR(x,y)
#else
# define PRINTF_ATTR(x,y) __attribute__ ((__format__ (__printf__, x, y)))
#endif

namespace {
const char *strcasestr_(const char *haystack, const char *needle, size_t needleLen = std::string::npos);
std::string base64Encode(const unsigned char *in, size_t in_len);
std::string sha1(const unsigned char *in, size_t len);
inline unsigned long long mono();
std::string format(const char *fmt, ...) PRINTF_ATTR(1, 2);
bool setNonblocking(int fd, std::string *err);
bool isBinary(const void *str, size_t len);
int verifyServerName(const std::string &hostname, const X509 *x509);
bool compareHost(const std::string expected, std::string actual);
int sslIndex();
size_t indexOf(const char *haystack, const char *needle);
std::string join(const std::vector<std::string> &strings, const std::string &delimiter);
std::vector<std::string> split(const std::string &string, const std::string &splitPattern);
}

std::unordered_map<SSL *, WebSocket *> WebSocket::sSockets;
bool WebSocket::verbose = false;
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
    trace("connect returned %d -> %d %s\n", ret, errno, strerror(errno));
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
        trace("TCP Connected!\n");
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

    mWss = !strncasecmp(mOptions.url.c_str(), "wss://", 6);
    if (options.connectTimeoutMS != 0)
        mConnectTimeout = mono() + options.connectTimeoutMS;
    return true;
}

void WebSocket::send(const std::string &text)
{
    wslay_event_msg wmsg = {
        WSLAY_TEXT_FRAME,
        reinterpret_cast<const unsigned char *>(text.c_str()),
        text.size()
    };
    // ### handle error somehow?
    if (!wslay_event_queue_msg(mContext, &wmsg))
        wslay_event_send(mContext);
}

void WebSocket::send(const std::vector<unsigned char> &binary)
{
    wslay_event_msg wmsg = {
        WSLAY_BINARY_FRAME,
        binary.empty() ? nullptr : &binary[0],
        binary.size()
    };
    // ### handle error somehow?
    if (!wslay_event_queue_msg(mContext, &wmsg))
        wslay_event_send(mContext);
}

bool WebSocket::close(uint16_t statusCode, const std::string &reason)
{
    return (!wslay_event_queue_close(mContext, statusCode,
                                     reinterpret_cast<const unsigned char *>(reason.c_str()), reason.size()) &&
            !wslay_event_send(mContext));
}

void WebSocket::prepareSelect(int &nfds, fd_set &r, fd_set &w, unsigned long long &timeout)
{
    trace("prepareSelect %s\n", stateToString(mState));
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
        break;
    case WebSocketConnecting:
        FD_SET(mFD, &r);
        FD_SET(mFD, &w);
        break;
    case WebSocketSentUpgrade:
        FD_SET(mFD, &r);
        break;
    case Connected:
        FD_SET(mFD, &r);
        if (!mContext) {
            createWSContext();
        }
        break;
    }

    if (mSSLWantsWrite) {
        trace("ssl wants write selecting for write\n");
        FD_SET(mFD, &w);
    }

    if (!mWriteBuffer.empty()) {
        trace("mWriteBuffer has %zu bytes, selecting for write\n", mWriteBuffer.size());
        FD_SET(mFD, &w);
    }
    nfds = std::max(nfds, mFD);
}

void WebSocket::processSelect(int count, const fd_set &r, const fd_set &w)
{
    mWokenUp = false;
    trace("processSelect %s count: %d - read: %d write: %d - pipe: %d\n", stateToString(mState),
          count, FD_ISSET(mFD, &r), FD_ISSET(mFD, &r), FD_ISSET(mPipe[0], &r));

    if (FD_ISSET(mPipe[0], &r)) {
        char buf;
        int r;
        EINTRWRAP(r, ::read(mPipe[0], &buf, 1));
        --count;
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
                trace("TCP CONNECTED!\n");
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
    case WebSocketConnecting:
        if (FD_ISSET(mFD, &w)) {
            assert(mUpgradeKey.empty());
            const std::string req = createUpgradeRequest();
            assert(!mUpgradeKey.empty());
            addToWriteBuffer(req.c_str(), req.size());
            writeSocketBuffer();
            mState = WebSocketSentUpgrade;
        }
        break;
    case WebSocketSentUpgrade:
        if (FD_ISSET(mFD, &w) && !mWriteBuffer.empty()) {
            writeSocketBuffer();
        }
        if (FD_ISSET(mFD, &r)) {
            char buf[1024];
            while (mState == WebSocketSentUpgrade) {
                int r = readData(buf, sizeof(buf));
                if (r == -1) {
                    if (errno != EWOULDBLOCK && errno != EAGAIN) {
                        trace("Got an error reading: %d %s\n",
                              errno, strerror(errno));
                        mState = Error;
                    }
                    break;
                } else if (!r) {
                    mState = Closed;
                    break;
                } else {
                    mUpgradeResponse.append(buf, r);
                    acceptUpgrade();
                }
            }
        }
        break;
    case Connected: {
        const bool writeBufferWasEmpty = mWriteBuffer.empty();
        if (FD_ISSET(mFD, &r)) {
            char buf[1024];
            while (true) {
                int r;
                EINTRWRAP(r, readData(buf, sizeof(buf)));
                if (r == -1) {
                    if (errno != EWOULDBLOCK && errno != EAGAIN) {
                        trace("Got an error reading: %d %s\n",
                              errno, strerror(errno));
                        mState = Error;
                    }
                    break;
                } else if (!r) {
                    mState = Closed;
                    break;
                } else {
                    const size_t size = mRecvBuffer.size();
                    mRecvBuffer.resize(mRecvBuffer.size() + r);
                    memcpy(&mRecvBuffer[size], buf, r);
                }
            }
            if (mState == Connected) {
                size_t old;
                do {
                    old = mRecvBuffer.size();
                    const int err = wslay_event_recv(mContext);
                    if (err < 0) {
                        trace("Something failed in wslay for %d closing %d (had %zu bytes, now has %zu bytes)",
                              mFD, err, old, mRecvBuffer.size());
                        mState = Error;
                        break;
                    }
                } while (mRecvBuffer.size() && old != mRecvBuffer.size());
            }
        }
        if (FD_ISSET(mFD, &w) || (writeBufferWasEmpty && !mWriteBuffer.empty())) {
            writeSocketBuffer();
        }

        break; }
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

const char *WebSocket::stateToString(State state)
{
    switch (state) {
    case Unset: return "Unset";
    case TCPConnecting: return "TCPConnecting";
    case SSLConnecting: return "SSLConnecting";
    case WebSocketConnecting: return "WebSocketConnecting";
    case WebSocketSentUpgrade: return "WebSocketSentUpgrade";
    case Connected: return "Connected";
    case Closed: return "Closed";
    case Error: return "Error";
    }
    return "";
}

// private functions

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

void WebSocket::acceptUpgrade()
{
    const char *data = mUpgradeResponse.c_str();
    if (!strstr(data, "\r\n\r\n"))
        return;
    const char *header = strcasestr_(data + 1, "\nsec-websocket-accept:");
    if (!header)
        return;
    trace("Got upgrade response\n%s\n", data);
    header += 22;
    while (isspace(static_cast<unsigned char>(*header)))
        ++header;

    if (!*header) {
        trace("WS: Invalid header\n");
        mState = Error;
        return;
    }

    const char *headerEnd = strstr(header, "\r\n");
    if (!headerEnd) {
        trace("WS: No crlf after Accept\n");
        mState = Error;
        return;
    }
    while (headerEnd > header && isspace(static_cast<unsigned char>(*(headerEnd - 1))))
        --headerEnd;

    std::string acceptKey = mUpgradeKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    acceptKey = sha1(reinterpret_cast<const unsigned char *>(acceptKey.c_str()), acceptKey.size());

    if (static_cast<size_t>(headerEnd - header) != acceptKey.size()) {
        trace("WS: Wrong key length %d %zu\n", static_cast<int>(headerEnd - header), acceptKey.size());
        mState = Error;
        return;
    }

    if (strncmp(header, acceptKey.c_str(), acceptKey.size())) {
        trace("WS: Wrong key %s %s", acceptKey.c_str(), std::string(header, headerEnd).c_str());
        mState = Error;
        return;
    }
    trace("Accepted ws handshake\n");
    mState = Connected;
}

void WebSocket::addToWriteBuffer(const void *data, size_t len)
{
    assert(len);
    size_t size = mWriteBuffer.size();
    mWriteBuffer.resize(size + len);
    memcpy(&mWriteBuffer[size], data, len);
    wakeup();
}

void WebSocket::writeSocketBuffer()
{
    trace("writeSocketBuffer %zu\n", mWriteBuffer.size());
    assert(!mWriteBuffer.empty());
    size_t written = 0;
    do {
        int w;
        assert(mWriteBuffer.size() > written);
        const unsigned char *data = &mWriteBuffer[0];
        if (mSSL) {
            w = SSL_write(mSSL, data + written, mWriteBuffer.size() - written);
            if (!w) {
                // seemingly not different anymore as per man SSL_write
                w = -1;
            }
        } else {
            EINTRWRAP(w, ::write(mFD, data + written, mWriteBuffer.size() - written));
        }
        if (w == -1) {
            if (mSSL) {
                const int sslErr = SSL_get_error(mSSL, w);
                switch (sslErr) {
                case SSL_ERROR_NONE:
                    trace("[WebSock.cpp:%d]: case SSL_ERROR_NONE:\n", __LINE__); fflush(stdout);
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    trace("[WebSock.cpp:%d]: case SSL_ERROR_ZERO_RETURN:\n", __LINE__); fflush(stdout);
                    mState = Closed;
                    break;
                case SSL_ERROR_WANT_READ:
                    trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_READ:\n", __LINE__); fflush(stdout);
                    break;
                case SSL_ERROR_WANT_WRITE:
                    trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_WRITE:\n", __LINE__); fflush(stdout);
                    break;
                case SSL_ERROR_WANT_CONNECT:
                    trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_CONNECT:\n", __LINE__); fflush(stdout);
                    break;
                case SSL_ERROR_WANT_ACCEPT:
                    trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_ACCEPT:\n", __LINE__); fflush(stdout);
                    break;
                case SSL_ERROR_WANT_ASYNC_JOB:
                    trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_ASYNC_JOB:\n", __LINE__); fflush(stdout);
                    break;
                case SSL_ERROR_WANT_CLIENT_HELLO_CB:
                    trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_CLIENT_HELLO_CB:\n", __LINE__); fflush(stdout);
                    break;
                case SSL_ERROR_SYSCALL:
                    trace("[WebSock.cpp:%d]: case SSL_ERROR_SYSCALL:\n", __LINE__); fflush(stdout);
                    mState = Error;
                    break;
                case SSL_ERROR_SSL:
                    trace("[WebSock.cpp:%d]: case SSL_ERROR_SSL:\n", __LINE__); fflush(stdout);
                    mState = Error;
                    break;
                default:
                    break;
                }
            } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
                trace("Got an error writing: %d %s\n",
                      errno, strerror(errno));
                mState = Error;
            } else {
                trace("Got EAGAIN writing %zu bytes\n", mWriteBuffer.size() - written);
            }
            break;
        } else {
            trace("Wrote %d bytes of %zu\n%s", w, mWriteBuffer.size() - written,
                  isBinary(data + written, w) ? "" : format("%.*s\n", w, data + written).c_str());
            assert(w > 0);
            written += w;
        }
    } while (written < mWriteBuffer.size());
    mWriteBuffer.erase(mWriteBuffer.begin(), mWriteBuffer.begin() + written);
}

int WebSocket::readData(void *buf, size_t bufSize)
{
    int r;
    if (!mSSL) {
        EINTRWRAP(r, ::read(mFD, buf, bufSize));
        return r;
    }

    mSSLWantsWrite = false;
    r = SSL_read(mSSL, buf, bufSize);
    if (r > 0) {
        return r;
    }
    const int sslErr = SSL_get_error(mSSL, r);
    switch (sslErr) {
    case SSL_ERROR_ZERO_RETURN:
        return 0;
    case SSL_ERROR_WANT_WRITE:
        mSSLWantsWrite = true;
        errno = EWOULDBLOCK;
        break;
    case SSL_ERROR_WANT_READ:
        errno = EWOULDBLOCK;
        break;
    case SSL_ERROR_SYSCALL:
        errno = EPROTO; // good enough
        break;
    default:
        assert(0);
        break;
    }
    return -1;
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
    SSL_CTX_set_ex_data(mSSLCtx, sslIndex(), this);
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
            trace("GOT HELLA X509 %p\n", x509);
            if (!x509)
                break;
            X509_STORE_add_cert(store, x509);
            X509_free(x509);
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
    trace("sslConnect wants write: %d - read: %d (%d) write: %d\n", mSSLWantsWrite,
          FD_ISSET(mFD, &r),
          FD_ISSET(mFD, &r) ? ([](int fd) -> int {
              int available;
              ioctl(fd, FIONREAD, &available);
              return available;
          })(mFD) : -1,
          FD_ISSET(mFD, &w));

    if (FD_ISSET(mFD, &r) || FD_ISSET(mFD, &w)) {
        ERR_clear_error();
        mSSLWantsWrite = false;
        const int connect = SSL_connect(mSSL);
        trace("CALLED CONNECT %d\n", connect);
        if (connect <= 0) {
            const int sslErr = SSL_get_error(mSSL, connect);
            switch (sslErr) {
            case SSL_ERROR_NONE:
                trace("[WebSock.cpp:%d]: case SSL_ERROR_NONE:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_ZERO_RETURN:
                trace("[WebSock.cpp:%d]: case SSL_ERROR_ZERO_RETURN:\n", __LINE__); fflush(stdout);
                mState = Closed;
                break;
            case SSL_ERROR_WANT_READ:
                trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_READ:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_WANT_WRITE:
                mSSLWantsWrite = true;
                trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_WRITE:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_WANT_CONNECT:
                trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_CONNECT:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_WANT_ACCEPT:
                trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_ACCEPT:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_WANT_ASYNC_JOB:
                trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_ASYNC_JOB:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
                trace("[WebSock.cpp:%d]: case SSL_ERROR_WANT_CLIENT_HELLO_CB:\n", __LINE__); fflush(stdout);
                break;
            case SSL_ERROR_SYSCALL:
                trace("[WebSock.cpp:%d]: case SSL_ERROR_SYSCALL:\n", __LINE__); fflush(stdout);
                mState = Error;
                break;
            case SSL_ERROR_SSL:
                trace("[WebSock.cpp:%d]: case SSL_ERROR_SSL:\n", __LINE__); fflush(stdout);
                mState = Error;
                break;
            default:
                break;
            }

            trace("GOT SSL ERR %d\n", sslErr);
        } else {
            assert(connect == 1);
            mState = WebSocketConnecting;
            processSelect(count, r, w);
        }
    }
}

int WebSocket::sslCtxVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    trace("Got sslCtxVerifyCallback %d\n", preverify_ok);
    if (preverify_ok != 1) {
        const unsigned long err = X509_STORE_CTX_get_error(x509_ctx);
        const char *errorString = X509_verify_cert_error_string(err);
        trace("Got ssl verify error: code: %ld text: %s\n",
              err, errorString);
        return preverify_ok;
    }

    const STACK_OF(X509) *xChain = X509_STORE_CTX_get0_chain(x509_ctx);
    assert(xChain);
    if (!xChain) {
        const unsigned long err = X509_STORE_CTX_get_error(x509_ctx);
        const char *errorString = X509_verify_cert_error_string(err);
        trace("Failed to get x509 chain: code: %ld text: %s\n",
              err, errorString);
        return 0;
    }

    const size_t numX509s = sk_X509_num(xChain);
    if (!numX509s) {
        const unsigned long err = X509_STORE_CTX_get_error(x509_ctx);
        const char *errorString = X509_verify_cert_error_string(err);
        trace("No certs in chain: code: %ld text: %s\n",
              err, errorString);
        return 0;
    }

    const X509 *x509 = sk_X509_value(xChain, 0);
    assert(x509);

    SSL *ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    assert(ssl);
    SSL_CTX *sslInitialCtx = SSL_get_SSL_CTX(ssl);
    WebSocket *webSocket = reinterpret_cast<WebSocket *>(SSL_CTX_get_ex_data(sslInitialCtx, sslIndex()));
    assert(webSocket);
    preverify_ok = verifyServerName(webSocket->mOptions.hostname, x509);
    return preverify_ok;
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
        trace("[WEBSOCK SSL] - %s: handshake done session %sreused\n", sock->mOptions.url.c_str(),
              SSL_session_reused(const_cast<SSL *>(ssl)) ? "" : "not ");
        // data->metrics.setSSLMode(SSL_session_reused(const_cast<SSL *>(ssl)) ? NetworkMetrics::SSLResumed : NetworkMetrics::SSL);
    }

    if (where & SSL_CB_LOOP) {
        trace("[WEBSOCK SSL] - %s: %s:%s\n", sock->mOptions.url.c_str(), str, SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
        trace("[WEBSOCK SSL] - %s: SSL3 alert %s:%s:%s\n", sock->mOptions.url.c_str(),
              str, SSL_alert_type_string_long(ret),
              SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT && ret <= 0) {
        trace("[WEBSOCK SSL] - %s: %s:%s in %s\n", sock->mOptions.url.c_str(), str, ret ? "error" : "failed",
               SSL_state_string_long(ssl));
    }
}


void WebSocket::createWSContext()
{
    assert(!mContext);
    wslay_event_callbacks callbacks = { wsRecv, wsSend, wsGenMask, nullptr, nullptr, nullptr, wsOnMessage };
    const int err = wslay_event_context_client_init(&mContext, &callbacks, this);
    assert(!err);
}

ssize_t WebSocket::wsSend(wslay_event_context *ctx, const uint8_t *data, size_t len, int flags, void *user_data)
{
    WebSocket *that = static_cast<WebSocket *>(user_data);
    that->addToWriteBuffer(data, len);
    trace("Sending %zu bytes of data for ws: %d\n", len, that->mFD);
    return len;
}

ssize_t WebSocket::wsRecv(wslay_event_context *ctx, uint8_t *data, size_t len, int flags, void *user_data)
{
    WebSocket *that = static_cast<WebSocket *>(user_data);
    if (that->mRecvBuffer.empty()) {
        wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        return -1;
    }
    const size_t ret = std::min(len, that->mRecvBuffer.size());
    memcpy(data, &that->mRecvBuffer[0], ret);
    // trace("Read %zd bytes:\n%s", ret, hexDump(data, ret));

    that->mRecvBuffer.erase(that->mRecvBuffer.begin(), that->mRecvBuffer.begin() + ret);
    return ret;
}

void WebSocket::wsOnMessage(wslay_event_context *, const wslay_event_on_msg_recv_arg *arg, void *user_data)
{
    WebSocket *that = static_cast<WebSocket *>(user_data);
    trace("WebSocket %d got a message opcode: 0x%x bytes: %zu\n",
           that->mFD, arg->opcode, arg->msg_length);
    switch (static_cast<wslay_opcode>(arg->opcode)) {
    case WSLAY_CONNECTION_CLOSE:
        // trace("Got close from server: statusCode: %d reason: \"%s\"",
        //        arg->status_code, ResourceManager::logString(arg->msg_length > 2 ? reinterpret_cast<const char *>(arg->msg) + 2 : "",
        //                                                     arg->msg_length > 2 ? arg->msg_length - 2 : 0));
        that->mState = Closed;
        if (that->mOptions.onClose) {
            CloseEvent event;
            event.statusCode = arg->status_code;
            // the first two bytes are the status code and wslay leaves them in
            // the message for some reason
            if (arg->msg_length > 2) {
                event.reason.assign(reinterpret_cast<const char *>(arg->msg) + 2, arg->msg_length - 2);
            }
            that->mOptions.onClose(that, std::move(event));
        }
        wslay_event_send(that->mContext);
        break;
    case WSLAY_PING:
    case WSLAY_PONG:
    case WSLAY_CONTINUATION_FRAME: {
        wslay_event_send(that->mContext);
        break; }
    case WSLAY_TEXT_FRAME:
    case WSLAY_BINARY_FRAME:
        if (that->mOptions.onMessage) {
            MessageEvent event;
            event.statusCode = arg->status_code;
            if (arg->msg_length) {
                if (arg->opcode == WSLAY_TEXT_FRAME) {
                    event.text.assign(reinterpret_cast<const char *>(arg->msg), arg->msg_length);
                } else {
                    event.binary.resize(arg->msg_length);
                    memcpy(&event.binary[0], arg->msg, arg->msg_length);
                }
            }

            that->mOptions.onMessage(that, std::move(event));
        }
        break;
    }
}

int WebSocket::wsGenMask(wslay_event_context */*ctx*/, uint8_t *buf, size_t len, void */*user_data*/)
{
    RAND_bytes(buf, len);
    return 0;
}

// ----------------------

namespace {
const char *strcasestr_(const char *haystack, const char *needle, size_t needleLen)
{
    if (needleLen == std::string::npos)
        needleLen = strlen(needle);
    assert(needle);
    assert(haystack);
    assert(needleLen);
    const char c = static_cast<char>(tolower(static_cast<unsigned char>(*needle++)));
    char sc;

    do {
        do {
            if ((sc = *haystack++) == 0)
                return nullptr;
        } while (static_cast<char>(tolower(static_cast<unsigned char>(sc))) != c);
    } while (strncasecmp(haystack, needle, needleLen - 1) != 0);
    --haystack;
    return haystack;
}

std::string base64Encode(const unsigned char* in, size_t in_len)
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

std::string sha1(const unsigned char *in, size_t in_len) // returns base 64 of the sha
{
    SHA_CTX context;
    if (!SHA1_Init(&context))
        std::string();

    unsigned char buf[SHA_DIGEST_LENGTH];
    SHA1_Update(&context, in, in_len);
    SHA1_Final(buf, &context);
    return base64Encode(buf, SHA_DIGEST_LENGTH);
}

unsigned long long mono()
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

bool setNonblocking(int fd, std::string *err)
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
bool isBinary(const void *data, size_t len)
{
    const unsigned char *ch = reinterpret_cast<const unsigned char *>(data);
    for (size_t i = 0; i < len; ++i) {
        switch (ch[i]) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 14:
        case 15:
        case 16:
        case 17:
        case 18:
        case 19:
        case 20:
        case 21:
        case 22:
        case 23:
        case 24:
        case 25:
        case 26:
        case 27:
        case 28:
        case 29:
        case 30:
        case 31:
            return true;
        default:
            if (ch[i] >= 127) {
                return true;
            }
            break;
        }
    }
    return false;
}

int verifyServerName(const std::string &expectedName, const X509 *x509)
{
    std::unique_ptr<BIO, int(*)(BIO *)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    X509_NAME *x509_name = X509_get_subject_name(x509);

    char certsubjectname[1024];
    int certsubjectnameLength = 0;

    if (x509_name && X509_NAME_print_ex(bio.get(), x509_name, 0, XN_FLAG_SEP_COMMA_PLUS) != -1) {
        certsubjectnameLength = std::max(0, BIO_read(bio.get(), certsubjectname, sizeof(certsubjectname) - 1));
        if (certsubjectnameLength <= 0) {
            trace("Failed to get name from X509\n");
        }
        certsubjectname[certsubjectnameLength] = '\0';
    } else {
        certsubjectname[0] = '\0';
        trace("Failed to get X509_NAME\n");
    }
    std::string cn;
    if (*certsubjectname) {
        trace("got certsubjectname %s\n", certsubjectname);
        const size_t idx  = indexOf(certsubjectname, ",CN=");
        if (idx != std::numeric_limits<size_t>::max() && idx + 4 < certsubjectnameLength) {
            size_t trailingComma = indexOf(certsubjectname + idx + 4, ",");
            if (!trailingComma) {
                trailingComma = certsubjectnameLength;
            }
            cn.assign(certsubjectname + idx + 4, trailingComma);
            if (compareHost(cn, expectedName)) {
                return 1;
            }
        }
    }

    std::unique_ptr<STACK_OF(GENERAL_NAME), void(*)(STACK_OF(GENERAL_NAME) *)> altNames(reinterpret_cast<STACK_OF(GENERAL_NAME) *>(X509_get_ext_d2i(x509, NID_subject_alt_name, nullptr, nullptr)),
                                                                                        &GENERAL_NAMES_free);
    if (!altNames) {
        trace("No alt names found\n");
        if (!cn.empty()) {
            trace("certificate subject name '%s' does not match target host name '%s'\n",
                  cn.c_str(), expectedName.c_str());
        } else {
            trace("No certificate subject name or alt names provided for expected host: '%s'\n",
                  expectedName.c_str());
        }
        return 0;
    }

    const int count = sk_GENERAL_NAME_num(altNames.get());
    std::vector<std::string> alternateNames;
    for (int idx = 0; idx < count; ++idx) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(altNames.get(), idx);
        assert(name);
        GENERAL_NAME_print(bio.get(), name);
        char buf[256];
        int read = BIO_read(bio.get(), buf, sizeof(buf));
        if (read > 4) {
            // the printing starts with DNS: hopefully it will forever do that
            std::string san(buf + 4, read - 4);
            if (compareHost(san, expectedName)) {
                trace("Found san that matched %s - %s\n", san.c_str(), expectedName.c_str());
                return 1;
            }
            alternateNames.push_back(std::move(san));
        }
    }

    if (!cn.empty()) {
        trace("certificate subject name '%s' or alternate names '%s' do not match '%s'\n",
              cn.c_str(), join(alternateNames, ", ").c_str(), expectedName.c_str());
    } else {
        trace("certificate alternate names '%s' do not match '%s'\n",
              join(alternateNames, ", ").c_str(), expectedName.c_str());
    }
    return 0;
}

bool compareHost(std::string actual, std::string expected)
{
    assert(!actual.empty());
    assert(!expected.empty());
    trace("compareHost %s %s\n", actual.c_str(), expected.c_str());

    if (actual[actual.length() - 1] == '.') {
        actual = actual.substr(0, actual.length() - 1);
    }
    if (expected[expected.length() - 1] == '.') {
        expected = expected.substr(0, expected.length() - 1);
    }

    const std::vector<std::string> actualSplit = split(actual, ".");
    if (strncmp(actual.c_str(), "*.", 2)) {
        const bool ret = actual == expected;
        trace("No starting wildcard, straight compare '%s' vs '%s' => %s\n",
              actual.c_str(), expected.c_str(), ret ? "true" : "false");
        return ret;
    }

    if (actualSplit.size() <= 2) {
        trace("actual has too few pieces (%zu)\n", actualSplit.size());
        return false;
    }

    const std::vector<std::string> expectedSplit = split(expected, ".");
    if (actualSplit.size() > expectedSplit.size()) {
        trace("actual has too many pieces, can't match '%s' vs '%s'",
              actual.c_str(), expected.c_str());
        return false;
    }

    size_t expectedIdx = expectedSplit.size() - actualSplit.size() + 1;
    for (size_t idx = 1; idx < actualSplit.size(); ++idx, ++expectedIdx) {
        if (actualSplit[idx] != expectedSplit[expectedIdx]) {
            trace("Failed compare '%s' %zu '%s' %zu\n",
                  actualSplit[idx].c_str(), idx, expectedSplit[expectedIdx].c_str(), expectedIdx);
            return false;
        }
        trace("Successful compare '%s' %zu '%s' %zu\n",
              actualSplit[idx].c_str(), idx, expectedSplit[expectedIdx].c_str(), expectedIdx);
    }
    return true;
}

int sslIndex()
{
    static int sSslIndex;
    static pthread_once_t sOnce = PTHREAD_ONCE_INIT;
    pthread_once(&sOnce, []() {
        sSslIndex = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    });
    return sSslIndex;
}
size_t indexOf(const char *haystack, const char *needle)
{
    const char *str = strstr(haystack, needle);
    if (!str) {
        return std::numeric_limits<size_t>::max();
    }
    return str - haystack;
}

std::string join(const std::vector<std::string> &strings, const std::string &delimiter)
{
    std::string ret;
    size_t reserve = delimiter.size() * (strings.size() - 1);
    for (const auto &ref : strings) {
        reserve += ref.size();
    }
    ret.reserve(reserve);
    for (const auto &ref : strings) {
        ret += ref;
    }
    return ret;
}

std::vector<std::string> split(const std::string &string, const std::string &delimiter)
{
    size_t last = 0;
    std::vector<std::string> ret;
    while (true) {
        const size_t next = string.find(delimiter, last);
        if (next == std::string::npos)
            break;
        ret.push_back(string.substr(last, next - last));
        last = next + 1;
    }
    ret.push_back(string.substr(last));
    return ret;
}
}
