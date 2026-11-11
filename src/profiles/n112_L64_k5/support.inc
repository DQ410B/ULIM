namespace fused_front {
using namespace ulim_gmw;using Bytes=std::vector<unsigned char>;
static void need(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}
template<class IO> static Bytes exchange(const Bytes& own, int party, IO& io) {
    need(own.size() <= INT_MAX, "public packet too long");
    Bytes peer(own.size());
    if (party == ALICE) {
        io.send_data(own.data(), own.size()); io.flush(); io.recv_data(peer.data(), peer.size());
    } else {
        io.recv_data(peer.data(), peer.size()); io.send_data(own.data(), own.size()); io.flush();
    }
    return peer;
}
static std::string quote(const std::string& x) {
    std::ostringstream o;
    o << '"';
    for (unsigned char c : x) {
        if (c == '"' || c == '\\') o << '\\' << c;
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if (c < 32) o << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << unsigned(c) << std::dec;
        else o << c;
    }
    o << '"';
    return o.str();
}
static uint64_t decimal(const char* text) {
    need(text && *text, "empty decimal argument");
    uint64_t x = 0;
    for (const char* p = text; *p; ++p) {
        need(*p >= '0' && *p <= '9', "nondecimal argument");
        const unsigned digit = unsigned(*p - '0');
        need(x <= (UINT64_MAX - digit) / 10, "decimal overflow");
        x = 10 * x + digit;
    }
    return x;
}
static void append32(Bytes& x, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) x.push_back(static_cast<unsigned char>(v >> (8 * i)));
}
static void append64(Bytes& x, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) x.push_back(static_cast<unsigned char>(v >> (8 * i)));
}
static uint32_t get32(const Bytes& x, size_t at) {
    need(at <= x.size() && x.size() - at >= 4, "uint32 decode range");
    uint32_t v = 0;
    for (unsigned i = 0; i < 4; ++i) v |= uint32_t(x[at + i]) << (8 * i);
    return v;
}
static uint64_t get64(const Bytes& x, size_t at) {
    need(at <= x.size() && x.size() - at >= 8, "uint64 decode range");
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= uint64_t(x[at + i]) << (8 * i);
    return v;
}
static void write_exact(int fd, const void* data, size_t size) {
    const auto* p = static_cast<const unsigned char*>(data);
    while (size) {
        ssize_t n = ::write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        need(n > 0, "file descriptor write failure");
        p += n;
        size -= static_cast<size_t>(n);
    }
}
static Bytes read_exact(int fd, size_t size) {
    Bytes x(size);
    size_t at = 0;
    while (at < size) {
        ssize_t n = ::read(fd, x.data() + at, size - at);
        if (n < 0 && errno == EINTR) continue;
        need(n > 0, "file descriptor read failure or unexpected EOF");
        at += static_cast<size_t>(n);
    }
    return x;
}
static void sync_exact(int fd) {
    int rc;
    do { rc = ::fsync(fd); } while (rc < 0 && errno == EINTR);
    need(rc == 0, "archive fsync failure");
}
struct Descriptor {
    int value = -1;
    Descriptor() = default;
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    ~Descriptor() { if (value >= 0) ::close(value); }
    void exclusive(const std::string& path) {
        value = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        need(value >= 0, "exclusive archive create failure");
    }
};
static Bytes hex_decode(const std::string& x) {
    need(x.size() == 64, "session must be exactly 64 lowercase hex characters");
    auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return unsigned(c - '0');
        if (c >= 'a' && c <= 'f') return unsigned(c - 'a' + 10);
        throw std::runtime_error("session must be lowercase hex");
    };
    Bytes out(32);
    for (size_t i = 0; i < out.size(); ++i) out[i] = static_cast<unsigned char>(16 * nibble(x[2 * i]) + nibble(x[2 * i + 1]));
    return out;
}
static std::string hex(const Bytes& x) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (unsigned char c : x) o << std::setw(2) << unsigned(c);
    return o.str();
}
static void padding(const Bytes& x, uint32_t width, uint32_t lanes) {
    const size_t stride = packed_bytes(width);
    need(x.size() == stride * lanes, "row-major size");
    if (width % 8) for (uint32_t l = 0; l < lanes; ++l)
        need((x[(l + 1) * stride - 1] >> (width % 8)) == 0, "nonzero row padding");
}
} // namespace fused_front
