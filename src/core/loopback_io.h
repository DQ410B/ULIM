#pragma once
// Bounded-task transport: an EMP-compatible buffered channel on 127.0.0.1 only.
// No vendor symbols or macros are replaced. Application-byte accounting is the
// inherited IOChannel counter, exactly as in the pinned EMP NetIO implementation.
#include <emp-tool/io/io_channel.h>
#include <emp-tool/utils/constants.h>
#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <fcntl.h>
#include <functional>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

class LoopbackIO : public emp::IOChannel<LoopbackIO> {
    int listener_ = -1;
    int connected_ = -1;
    std::array<unsigned char, emp::NETWORK_BUFFER_SIZE> buffer_{};
    size_t used_ = 0;
    std::string local_ipv4_, peer_ipv4_;
    std::function<void(bool, const unsigned char*, size_t)> wire_observer_;

    [[noreturn]] static void fail(const char* operation) {
        const int code = errno;
        throw std::runtime_error(std::string(operation) + ": " + std::strerror(code));
    }
    static void require(bool ok, const char* message) {
        if (!ok) throw std::runtime_error(message);
    }
    static void close_owned(int& fd) noexcept {
        if (fd >= 0) {
            // Do not retry close after EINTR: the descriptor may already have
            // been released and reused on some supported POSIX systems.
            ::close(fd);
            fd = -1;
        }
    }
    void cleanup() noexcept {
        close_owned(listener_);
        close_owned(connected_);
    }
    static int open_socket() {
        int fd;
        do { fd = ::socket(AF_INET, SOCK_STREAM, 0); } while (fd < 0 && errno == EINTR);
        if (fd < 0) fail("loopback socket");
        int flags;
        do { flags = ::fcntl(fd, F_GETFD); } while (flags < 0 && errno == EINTR);
        int rc = -1;
        if (flags >= 0) do { rc = ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC); } while (rc < 0 && errno == EINTR);
        if (flags < 0 || rc < 0) {
            const int code = errno;
            ::close(fd);
            errno = code;
            fail("loopback socket close-on-exec");
        }
        return fd;
    }
    static void option(int fd, int level, int name, int value) {
        int rc;
        do { rc = ::setsockopt(fd, level, name, &value, sizeof(value)); } while (rc < 0 && errno == EINTR);
        if (rc < 0) fail("loopback socket option");
    }
    static sockaddr_in address(uint16_t port) {
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(port);
        return a;
    }
    static void bind_loopback(int fd, uint16_t port) {
        const auto a = address(port);
        int rc;
        do { rc = ::bind(fd, reinterpret_cast<const sockaddr*>(&a), sizeof(a)); } while (rc < 0 && errno == EINTR);
        if (rc < 0) fail("bind 127.0.0.1");
    }
    static void retry_pause() {
        timespec remaining{0, 1000000};
        while (::nanosleep(&remaining, &remaining) < 0) {
            if (errno != EINTR) fail("loopback connection retry pause");
        }
    }
    void validate_endpoints() {
        sockaddr_in local{}, peer{};
        socklen_t local_size = sizeof(local), peer_size = sizeof(peer);
        int rc;
        do { rc = ::getsockname(connected_, reinterpret_cast<sockaddr*>(&local), &local_size); } while (rc < 0 && errno == EINTR);
        if (rc < 0) fail("loopback getsockname");
        do { rc = ::getpeername(connected_, reinterpret_cast<sockaddr*>(&peer), &peer_size); } while (rc < 0 && errno == EINTR);
        if (rc < 0) fail("loopback getpeername");
        require(local_size == sizeof(local) && peer_size == sizeof(peer) &&
            local.sin_family == AF_INET && peer.sin_family == AF_INET &&
            local.sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
            peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
            "transport endpoints must both be exactly 127.0.0.1");
        char local_text[INET_ADDRSTRLEN], peer_text[INET_ADDRSTRLEN];
        if (!::inet_ntop(AF_INET, &local.sin_addr, local_text, sizeof(local_text))) fail("loopback local inet_ntop");
        if (!::inet_ntop(AF_INET, &peer.sin_addr, peer_text, sizeof(peer_text))) fail("loopback peer inet_ntop");
        local_ipv4_ = local_text;
        peer_ipv4_ = peer_text;
    }
    void send_exact(const unsigned char* data, size_t size) {
        while (size) {
#ifdef MSG_NOSIGNAL
            const ssize_t sent = ::send(connected_, data, size, MSG_NOSIGNAL);
#else
            const ssize_t sent = ::send(connected_, data, size, 0);
#endif
            if (sent < 0 && errno == EINTR) continue;
            if (sent < 0) fail("loopback send");
            require(sent > 0, "loopback send made no progress");
            actual_sent += static_cast<uint64_t>(sent);
            if (wire_observer_) wire_observer_(true, data, static_cast<size_t>(sent));
            data += static_cast<size_t>(sent);
            size -= static_cast<size_t>(sent);
        }
    }
public:
    uint64_t received = 0;
    uint64_t actual_sent = 0;
    // There is deliberately no caller-supplied remote address. Startup retry is
    // limited to refused/interrupted loopback connection attempts and is bounded
    // by the external continuous-clock supervisor, as is an absent peer.
    explicit LoopbackIO(bool server, int port) {
        require(port >= 1024 && port <= 65535, "loopback port range");
        try {
            if (server) {
                listener_ = open_socket();
                option(listener_, SOL_SOCKET, SO_REUSEADDR, 1);
                bind_loopback(listener_, static_cast<uint16_t>(port));
                int rc;
                do { rc = ::listen(listener_, 1); } while (rc < 0 && errno == EINTR);
                if (rc < 0) fail("loopback listen");
                sockaddr_in accepted{};
                socklen_t size = sizeof(accepted);
                do {
                    size = sizeof(accepted);
                    connected_ = ::accept(listener_, reinterpret_cast<sockaddr*>(&accepted), &size);
                } while (connected_ < 0 && errno == EINTR);
                if (connected_ < 0) fail("loopback accept");
                require(size == sizeof(accepted) && accepted.sin_family == AF_INET &&
                    accepted.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
                    "accepted peer is not exactly 127.0.0.1");
                close_owned(listener_);
            } else {
                const auto destination = address(static_cast<uint16_t>(port));
                while (true) {
                    connected_ = open_socket();
                    bind_loopback(connected_, 0);
                    if (::connect(connected_, reinterpret_cast<const sockaddr*>(&destination), sizeof(destination)) == 0) break;
                    const int code = errno;
                    close_owned(connected_);
                    if (code != ECONNREFUSED && code != EINTR) {
                        errno = code;
                        fail("connect 127.0.0.1");
                    }
                    retry_pause();
                }
            }
            // Accepted descriptors do not portably inherit close-on-exec.
            int flags, rc;
            do { flags = ::fcntl(connected_, F_GETFD); } while (flags < 0 && errno == EINTR);
            if (flags < 0) fail("connected loopback descriptor flags");
            do { rc = ::fcntl(connected_, F_SETFD, flags | FD_CLOEXEC); } while (rc < 0 && errno == EINTR);
            if (rc < 0) fail("connected loopback close-on-exec");
            option(connected_, IPPROTO_TCP, TCP_NODELAY, 1);
#ifdef SO_NOSIGPIPE
            option(connected_, SOL_SOCKET, SO_NOSIGPIPE, 1);
#endif
            validate_endpoints();
        } catch (...) {
            cleanup();
            throw;
        }
    }
    LoopbackIO(const LoopbackIO&) = delete;
    LoopbackIO& operator=(const LoopbackIO&) = delete;
    ~LoopbackIO() { cleanup(); }
    const std::string& local_ipv4() const { return local_ipv4_; }
    const std::string& peer_ipv4() const { return peer_ipv4_; }
    void set_wire_observer(std::function<void(bool, const unsigned char*, size_t)> observer) {
        require(counter == 0 && received == 0 && actual_sent == 0,
                "wire observer must be installed before protocol IO");
        wire_observer_ = std::move(observer);
    }
    void flush() {
        if (used_) {
            send_exact(buffer_.data(), used_);
            used_ = 0;
        }
    }
    void send_data_internal(const void* data, size_t length) {
        const auto* input = static_cast<const unsigned char*>(data);
        while (length) {
            const size_t count = std::min(length, buffer_.size() - used_);
            std::memcpy(buffer_.data() + used_, input, count);
            used_ += count;
            input += count;
            length -= count;
            if (used_ == buffer_.size()) flush();
        }
    }
    void recv_data_internal(void* data, size_t length) {
        // Match NetIO's send-before-receive flush behavior, without a mixed
        // read/write stdio stream. Received bytes are read exactly as requested.
        flush();
        auto* output = static_cast<unsigned char*>(data);
        while (length) {
            const ssize_t received = ::recv(connected_, output, length, 0);
            if (received < 0 && errno == EINTR) continue;
            if (received < 0) fail("loopback receive");
            require(received > 0, "loopback peer closed before complete message");
            this->received += static_cast<uint64_t>(received);
            if (wire_observer_) wire_observer_(false, output, static_cast<size_t>(received));
            output += static_cast<size_t>(received);
            length -= static_cast<size_t>(received);
        }
    }
};
