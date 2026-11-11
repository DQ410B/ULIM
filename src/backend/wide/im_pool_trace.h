#pragma once
// Qualification-only local evidence for matched D/G n17. Never instantiated in benchmark.
// Archives contain each party's own private view and are not public outputs.
#include "src/backend/wide/standard_triple_producer.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

namespace ulim_standard_im_evidence {
using Bytes = std::vector<uint8_t>;
using Binding = ulim_standard_fresh::Binding;
inline void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

class File {
    int fd_ = -1;
    uint64_t count_ = 0;
    uint64_t cap_;
    bool failed_ = false;
public:
    File(const std::string& path, uint64_t cap): cap_(cap) {
        fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        require(fd_ >= 0, "exclusive standard IM evidence create");
    }
    ~File() noexcept { if (fd_ >= 0) ::close(fd_); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    void put(const void* data, size_t length) {
        require(fd_ >= 0 && !failed_, "standard IM evidence stream unavailable");
        require(length <= cap_ - count_, "standard IM evidence byte cap");
        const auto* bytes = static_cast<const uint8_t*>(data);
        try {
            while (length) {
                const ssize_t n = ::write(fd_, bytes, length);
                if (n < 0 && errno == EINTR) continue;
                require(n > 0, "standard IM evidence write");
                const auto used = static_cast<size_t>(n);
                count_ += used;
                bytes += used;
                length -= used;
            }
        } catch (...) { failed_ = true; throw; }
    }
    void u64(uint64_t word) {
        uint8_t bytes[8];
        for (unsigned i = 0; i < 8; ++i) bytes[i] = uint8_t(word >> (8*i));
        put(bytes, sizeof(bytes));
    }
    void finish() {
        require(fd_ >= 0 && !failed_, "standard IM evidence finish state");
        int rc;
        do { rc = ::fsync(fd_); } while (rc < 0 && errno == EINTR);
        if (rc != 0) { failed_ = true; throw std::runtime_error("standard IM evidence sync"); }
        const int closing = fd_;
        fd_ = -1;  // Never retry close after EINTR; the descriptor may be reused.
        if (::close(closing) != 0) { failed_ = true; throw std::runtime_error("standard IM evidence close"); }
    }
    uint64_t count() const { return count_; }
};

class Archive {
    int party_;
    Binding binding_;
    uint64_t expected_G_, expected_batches_, expected_requests_, expected_segments_;
    File pool_, sent_, received_;
    uint64_t records_ = 0, ot_count_ = 0, pool_count_ = 0;
    bool finished_ = false, failed_ = false;
    static Bytes bytes(const std::array<uint8_t,32>& value) {
        return Bytes(value.begin(), value.end());
    }
    void record(uint64_t kind, const std::vector<uint64_t>& words,
                const std::vector<const Bytes*>& vectors) {
        require(!finished_ && !failed_ && records_ < 2 + 3 * expected_batches_, "standard IM evidence record state");
        try {
            pool_.u64(kind); pool_.u64(words.size()); pool_.u64(vectors.size());
            for (uint64_t value: words) pool_.u64(value);
            for (const auto* vector: vectors) {
                pool_.u64(vector->size());
                if (!vector->empty()) pool_.put(vector->data(), vector->size());
            }
            ++records_;
        } catch (...) { failed_ = true; throw; }
    }
public:
    Archive(const std::string& directory, int party, const Binding& binding,
            uint64_t G,uint64_t batches,uint64_t requests,uint64_t segments)
        : party_(party), binding_(binding), expected_G_(G), expected_batches_(batches),
          expected_requests_(requests), expected_segments_(segments),
          pool_(directory + "/ot_pool.bin", 128ULL << 20),
          sent_(directory + "/sent.bin", 256ULL << 20),
          received_(directory + "/received.bin", 256ULL << 20) {
        require(party == 1 || party == 2, "standard IM evidence party");
        require((G==2022399&&batches==31&&requests==4959&&segments==4989)||
                (G==1139911&&batches==18&&requests==17072&&segments==17089),"matched qualification exact D/G n17 profile");
        pool_.put("ULIMIP01", 8);
        const auto bound = bytes(binding_);
        record(0, {uint64_t(party_), ulim_standard_fresh::kBatchBits, 0}, {&bound});
    }
    Archive(const Archive&) = delete;
    Archive& operator=(const Archive&) = delete;
    void on_wire(bool sent, const unsigned char* data, size_t length) {
        require(!finished_ && !failed_, "standard IM wire evidence state");
        try { (sent ? sent_ : received_).put(data, length); }
        catch (...) { failed_ = true; throw; }
    }
    void on_ot(const ulim_standard_ot::TransferObservation& event) {
        require(event.party == party_ && event.binding == binding_, "standard IM OT binding");
        require(ot_count_ < 2 * expected_batches_ && event.direction == int(ot_count_ % 2) &&
                event.sender == (party_ == event.direction + 1) &&
                event.global_begin == pool_count_ * ulim_standard_fresh::kBatchBits &&
                event.bit_count == ulim_standard_fresh::kBatchBits &&
                ot_count_ == 2 * pool_count_ + (event.direction == 1 ? 1 : 0),
                "standard IM matched D/G n17 OT schedule");
        require(event.raw_blocks.size() == ulim_standard_fresh::kBatchBits * 16 &&
                event.ciphertexts.size() == ulim_standard_fresh::kBatchBits / 4,
                "standard IM OT raw/cipher shape");
        require(event.sender_delta.size() == (event.sender ? 16 : 0) &&
                event.m0.size() == (event.sender ? ulim_standard_fresh::kBatchBits / 8 : 0) &&
                event.m1.size() == (event.sender ? ulim_standard_fresh::kBatchBits / 8 : 0) &&
                event.choices.size() == (event.sender ? 0 : ulim_standard_fresh::kBatchBits / 8) &&
                event.output.size() == (event.sender ? 0 : ulim_standard_fresh::kBatchBits / 8), "standard IM OT role shape");
        const auto bound=bytes(event.binding), sid=bytes(event.sid);
        const auto n0=bytes(event.nonce_p0), n1=bytes(event.nonce_p1);
        record(1, {uint64_t(event.party),uint64_t(event.direction),uint64_t(event.sender),
                   event.global_begin,event.bit_count},
               {&bound,&sid,&n0,&n1,&event.sender_delta,&event.raw_blocks,
                &event.m0,&event.m1,&event.choices,&event.ciphertexts,&event.output});
        ++ot_count_;
    }
    void on_pool(const ulim_standard_fresh::PoolObservation& event) {
        require(pool_count_ < expected_batches_ && ot_count_ == 2 * (pool_count_ + 1) &&
                event.batch_id == pool_count_ &&
                event.global_begin == pool_count_ * ulim_standard_fresh::kBatchBits,
                "standard IM matched D/G n17 pool schedule");
        for (const auto* vector: {&event.a,&event.b,&event.r,&event.incoming,&event.c})
            require(vector->size() == ulim_standard_fresh::kBatchBits / 8, "standard IM pool vector shape");
        record(2, {event.batch_id,event.global_begin,ulim_standard_fresh::kBatchBits}, {&event.a,&event.b,&event.r,&event.incoming,&event.c});
        ++pool_count_;
    }
    void finish(uint64_t produced, uint64_t consumed, uint64_t delivered, uint64_t discarded,
                uint64_t unused, uint64_t batches, uint64_t requests, uint64_t segments,
                uint64_t sent, uint64_t received) {
        require(!finished_&&!failed_&&batches==expected_batches_&&produced==batches*ulim_standard_fresh::kBatchBits&&
                consumed==expected_G_&&delivered==expected_G_&&discarded==0&&unused==produced-consumed&&
                requests==expected_requests_&&segments==expected_segments_&&
                ot_count_==2*batches&&pool_count_==batches&&records_==1+3*batches,
                "matched standard IM archive exact profile");
        require(sent_.count() == sent && received_.count() == received,
                "standard IM actual wire byte closure");
        record(9, {produced,consumed,delivered,discarded,unused,batches,requests,segments,
                   ot_count_,pool_count_,sent,received}, {});
        try { pool_.finish(); sent_.finish(); received_.finish(); }
        catch (...) { failed_ = true; throw; }
        finished_ = true;
    }
    bool finished() const { return finished_; }
};
} // namespace ulim_standard_im_evidence
