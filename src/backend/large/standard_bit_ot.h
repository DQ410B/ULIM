#pragma once

// Candidate standard-OT backend, separate from the existing LPN producers.
// Security model: one static semi-honest corruption, applicable base OT and
// hidden-key PRGs, and SHA-256 modeled as a random oracle. A SID is domain
// separation, not peer authentication. The caller must agree binding before
// initialize(), on the same reliable authenticated logical session.
// This header does not assert a concrete native security proof or sanitizer.
#include <emp-tool/emp-tool.h>
#include <emp-ot/iknp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "src/backend/large/parallel_pad.h"

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace ulim_standard_ot {

using Bytes = std::vector<uint8_t>;
inline constexpr uint64_t kBatchBits = 65536;
inline constexpr size_t kPackedBytes = size_t(kBatchBits / 8);
inline constexpr size_t kCipherBytes = size_t(kBatchBits / 4);
using PhaseHook = std::function<void(
    int direction, const std::string& name, const std::function<void()>& work)>;

// Canonical block bytes: least-significant 64-bit lane first, each lane LE.
// Neither the pad domain nor observer files use a truncated/normalized block.
inline std::array<uint8_t, 16> canonical_block(const emp::block& value) {
    static_assert(CHAR_BIT == 8 && sizeof(emp::block) == 16,
                  "standard bit OT requires 8-bit bytes and 128-bit blocks");
    const uint64_t low = static_cast<uint64_t>(_mm_cvtsi128_si64(value));
    const uint64_t high = static_cast<uint64_t>(
        _mm_cvtsi128_si64(_mm_srli_si128(value, 8)));
    std::array<uint8_t, 16> bytes{};
    for (unsigned j = 0; j < 8; ++j) {
        bytes[j] = uint8_t(low >> (8 * j));
        bytes[8 + j] = uint8_t(high >> (8 * j));
    }
    return bytes;
}

// Qualification-only borrowed view. Every byte is from this local transfer.
// The callback is synchronous, once before its direction cursor commits. It
// must consume immediately, retain no references, and maintain bounded state.
// Default: no observer. It sends no extra peer messages and exposes no peer
// private inputs. Combining both parties' observer files reveals secret data.
struct TransferObservation {
    int party;
    int direction;
    bool sender;
    uint64_t global_begin;
    uint64_t bit_count;
    const std::array<uint8_t, 32>& binding;
    const std::array<uint8_t, 32>& sid;
    const std::array<uint8_t, 32>& nonce_p0;
    const std::array<uint8_t, 32>& nonce_p1;
    const Bytes& sender_delta; // Sender: 16 canonical bytes. Receiver: empty.
    const Bytes& raw_blocks;  // 16 * bit_count bytes: local Q or local T.
    const Bytes& m0;          // Sender: 8192 bytes. Receiver: empty.
    const Bytes& m1;          // Sender: 8192 bytes. Receiver: empty.
    const Bytes& choices;     // Receiver: 8192 bytes. Sender: empty.
    const Bytes& ciphertexts; // Actual fixed 16384 bytes sent or received.
    const Bytes& output;      // Receiver: 8192 bytes. Sender: empty.
};
using Observer = std::function<void(const TransferObservation&)>;

template<class IO>
class StandardOtBitAdapter {
public:
    using Observer = ulim_standard_ot::Observer;
    using PhaseHook = ulim_standard_ot::PhaseHook;

private:
    struct Control {
        bool alive = true;
        bool busy = false;
        bool poisoned = false;
    };
    // Shared only to reject a hook's saved work closure safely after its phase
    // or adapter has ended. No asynchronous use or cross-thread use is allowed.
    struct PhaseTicket {
        bool open = true;
        bool invoked = false;
        bool complete = false;
        bool failed = false;
    };
    class Operation {
        std::shared_ptr<Control> control_;
        bool complete_ = false;
    public:
        explicit Operation(const std::shared_ptr<Control>& control)
            : control_(control) {
            if (!control_->alive || control_->poisoned)
                throw std::runtime_error("standard bit OT adapter poisoned");
            if (control_->busy) {
                control_->poisoned = true;
                throw std::runtime_error("standard bit OT adapter reentrancy");
            }
            control_->busy = true;
        }
        ~Operation() {
            if (!complete_) control_->poisoned = true;
            control_->busy = false;
        }
        void finish() {
            if (control_->poisoned)
                throw std::runtime_error("standard bit OT operation poisoned");
            complete_ = true;
        }
        Operation(const Operation&) = delete;
        Operation& operator=(const Operation&) = delete;
    };

    int party_;
    IO& io_;
    std::array<uint8_t, 32> binding_{};
    std::array<uint8_t, 32> sid_{};
    std::array<uint8_t, 32> nonce_p0_{};
    std::array<uint8_t, 32> nonce_p1_{};
    std::shared_ptr<Control> control_ = std::make_shared<Control>();
    std::array<std::unique_ptr<emp::IKNP<IO>>, 2> core_;
    std::array<bool, 2> setup_complete_{{false, false}};
    std::array<uint64_t, 2> next_{{0, 0}};
    int next_direction_ = 0;
    bool initialized_ = false;
    Observer observer_;
    ulim_parallel_pad::Workers pad_workers_;

    static void require(bool ok, const char* message) {
        if (!ok) throw std::runtime_error(message);
    }
    static uint8_t bit(const Bytes& bytes, uint64_t index) {
        return uint8_t((bytes[size_t(index / 8)] >> unsigned(index & 7)) & 1u);
    }
    static void put_bit(Bytes& bytes, uint64_t index, uint8_t value) {
        // Every destination is zero-initialized and each bit is written once.
        bytes[size_t(index / 8)] |= uint8_t((value & 1u) << unsigned(index & 7));
    }
    static void le64(uint8_t* output, uint64_t value) {
        for (unsigned j = 0; j < 8; ++j) output[j] = uint8_t(value >> (8 * j));
    }
    static std::array<uint8_t, 32> hash(const uint8_t* input, size_t bytes) {
        std::array<uint8_t, 32> output{};
        require(SHA256(input, bytes, output.data()) != nullptr,
                "standard bit OT SHA256 failure");
        return output;
    }
    static uint8_t pad(std::array<uint8_t, 65>& input,
                       uint64_t coordinate, const emp::block& raw,
                       ulim_parallel_pad::HashMode mode) {
        le64(input.data() + 41, coordinate);
        const auto encoded = canonical_block(raw);
        std::copy(encoded.begin(), encoded.end(), input.begin() + 49);
        // Explicit bit convention: bit 0 of byte 0 of the SHA-256 digest.
        std::array<uint8_t,32> digest{};
        ulim_parallel_pad::digest65(input.data(), digest.data(), mode);
        return uint8_t(digest[0] & 1u);
    }
    bool sender_for(int direction) const {
        return (direction == 0 && party_ == 1) ||
               (direction == 1 && party_ == 2);
    }

    void phase(int direction, const std::string& name,
               const std::function<void()>& work, const PhaseHook& hook) {
        auto ticket = std::make_shared<PhaseTicket>();
        const auto control = control_;
        const std::function<void()> guarded = [this, ticket, control, work] {
            if (!ticket->open || ticket->invoked || !control->alive ||
                control->poisoned) {
                control->poisoned = true;
                ticket->failed = true;
                throw std::runtime_error("standard bit OT phase work is not one-shot synchronous");
            }
            ticket->invoked = true;
            try {
                work();
                io_.flush();
                require(!control->poisoned, "standard bit OT phase poisoned by callback");
                ticket->complete = true;
            } catch (...) {
                ticket->failed = true;
                control->poisoned = true;
                throw;
            }
        };
        try {
            if (hook) hook(direction, name, guarded);
            else guarded();
        } catch (...) {
            ticket->open = false;
            control_->poisoned = true;
            throw;
        }
        ticket->open = false;
        require(ticket->invoked && ticket->complete && !ticket->failed &&
                    !control_->poisoned,
                "standard bit OT phase hook must finish work exactly once");
    }

public:
    // Creates two separate raw IKNP objects. Their constructors communicate
    // nothing; their inherited pinned EMP RNG initialization is unchanged.
    StandardOtBitAdapter(int party, IO& io,
                         std::array<uint8_t, 32> agreed_binding)
        : party_(party), io_(io), binding_(agreed_binding) {
        static_assert(kBatchBits % 2048 == 0 && kBatchBits % 128 == 0,
                      "raw IKNP calls must never have a partial block");
        require(party_ == 1 || party_ == 2, "standard bit OT party must be 1 or 2");
        core_[0].reset(new emp::IKNP<IO>(&io_, false));
        core_[1].reset(new emp::IKNP<IO>(&io_, false));
    }
    ~StandardOtBitAdapter() { control_->alive = false; }
    StandardOtBitAdapter(const StandardOtBitAdapter&) = delete;
    StandardOtBitAdapter& operator=(const StandardOtBitAdapter&) = delete;
    StandardOtBitAdapter(StandardOtBitAdapter&&) = delete;
    StandardOtBitAdapter& operator=(StandardOtBitAdapter&&) = delete;

    void set_observer(Observer observer) {
        Operation operation(control_);
        require(!initialized_, "standard bit OT observer must be set before initialize");
        observer_ = std::move(observer);
        operation.finish();
    }

    // Idempotent only after a successful first initialization. P0 sends 32
    // bytes then receives; P1 receives then sends. Both-sent payload: 64 bytes.
    void initialize() {
        Operation operation(control_);
        if (initialized_) {
            operation.finish();
            return;
        }
        std::array<uint8_t, 32> own{}, peer{};
        require(RAND_bytes(own.data(), int(own.size())) == 1,
                "standard bit OT nonce RAND_bytes failure");
        if (party_ == 1) {
            io_.send_data(own.data(), own.size());
            io_.flush();
            io_.recv_data(peer.data(), peer.size());
            nonce_p0_ = own;
            nonce_p1_ = peer;
        } else {
            io_.recv_data(peer.data(), peer.size());
            io_.send_data(own.data(), own.size());
            io_.flush();
            nonce_p0_ = peer;
            nonce_p1_ = own;
        }
        std::array<uint8_t, 104> input{};
        const std::array<uint8_t, 8> domain{{'U','L','I','M','S','I','D','1'}};
        std::copy(domain.begin(), domain.end(), input.begin());
        std::copy(binding_.begin(), binding_.end(), input.begin() + 8);
        std::copy(nonce_p0_.begin(), nonce_p0_.end(), input.begin() + 40);
        std::copy(nonce_p1_.begin(), nonce_p1_.end(), input.begin() + 72);
        sid_ = hash(input.data(), input.size());
        initialized_ = true;
        operation.finish();
    }

    // Alternating dir0 then dir1, complete 65536-row batches only. Each
    // direction owns a persistent raw IKNP setup and a monotone row cursor.
    // Public role/shape checks happen before cryptographic state is consumed.
    Bytes transfer(int direction, uint64_t global_begin,
                   const Bytes& m0, const Bytes& m1, const Bytes& choices,
                   PhaseHook hook = {}) {
        Operation operation(control_);
        require(initialized_, "standard bit OT initialize required before transfer");
        require(direction == 0 || direction == 1, "standard bit OT direction");
        require(direction == next_direction_, "standard bit OT directions must alternate 0 then 1");
        const size_t d = size_t(direction);
        require(global_begin == next_[d], "standard bit OT coordinate continuity");
        require(global_begin <= std::numeric_limits<uint64_t>::max() - kBatchBits,
                "standard bit OT coordinate overflow");
        const uint64_t global_end = global_begin + kBatchBits;
        const bool sender = sender_for(direction);
        if (sender) {
            require(m0.size() == kPackedBytes && m1.size() == kPackedBytes && choices.empty(),
                    "standard bit OT sender input shape");
        } else {
            require(m0.empty() && m1.empty() && choices.size() == kPackedBytes,
                    "standard bit OT receiver input shape");
        }
        require(core_[d] && !core_[d]->malicious &&
                    core_[d]->setup == setup_complete_[d],
                "standard bit OT raw core state");

        // Freeze entry values before any caller hook/IO callback can run.
        // Matrix choices, selected ciphertext bits and observer inputs must
        // refer to the same actual local input, even if the caller owns aliases.
        const Bytes messages0 = m0;
        const Bytes messages1 = m1;
        const Bytes choice_bits = choices;
        // Per-call temporary storage is bounded by the fixed public batch.
        std::unique_ptr<emp::block[]> raw(new emp::block[size_t(kBatchBits)]);
        std::unique_ptr<bool[]> unpacked;
        if (!sender) {
            unpacked.reset(new bool[size_t(kBatchBits)]);
            for (uint64_t j = 0; j < kBatchBits; ++j)
                unpacked[size_t(j)] = bit(choice_bits, j) != 0;
        }
        Bytes ciphertexts(kCipherBytes, 0);
        Bytes output(sender ? 0 : kPackedBytes, 0);
        std::array<uint8_t, 65> hash_input{};
        const std::array<uint8_t, 8> domain{{'U','L','I','M','O','T','0','1'}};
        std::copy(domain.begin(), domain.end(), hash_input.begin());
        std::copy(sid_.begin(), sid_.end(), hash_input.begin() + 8);
        hash_input[40] = uint8_t(direction);

        if (!setup_complete_[d]) {
            phase(direction, "base_ot_setup", [&] {
                // No supplied s or seeds: raw setup samples all 128 Delta
                // bits. Never normalize Delta or outputs, and never reseed.
                if (sender) core_[d]->setup_send();
                else core_[d]->setup_recv();
                require(core_[d]->setup && !core_[d]->malicious,
                        "standard bit OT raw setup completion");
            }, hook);
            setup_complete_[d] = true;
        }
        phase(direction, "matrix", [&] {
            // These raw methods do not call COT::send/recv or MITCCRH.
            // A full multiple of 2048 avoids the pinned partial transpose.
            if (sender) core_[d]->send_cot(raw.get(), int64_t(kBatchBits));
            else core_[d]->recv_cot(raw.get(), unpacked.get(), int64_t(kBatchBits));
        }, hook);
        phase(direction, "bit_ot", [&] {
            const auto mode = pad_workers_.mode();
            emp::block* const raw_pointer = raw.get();
            if (sender) {
                const emp::block delta = core_[d]->Delta;
                pad_workers_.run(size_t(kBatchBits/8),
                    [raw_pointer,delta,hash_input,global_begin,mode,&messages0,&messages1,&ciphertexts](size_t lo,size_t hi) {
                    auto local_input = hash_input;
                    for (uint64_t j = uint64_t(lo)*8; j < uint64_t(hi)*8; ++j) {
                        const emp::block q = raw_pointer[size_t(j)];
                        const emp::block q_delta = q ^ delta;
                        const uint8_t h0 = pad(local_input,global_begin+j,q,mode);
                        const uint8_t h1 = pad(local_input,global_begin+j,q_delta,mode);
                        put_bit(ciphertexts,2*j,uint8_t(bit(messages0,j)^h0));
                        put_bit(ciphertexts,2*j+1,uint8_t(bit(messages1,j)^h1));
                    }
                });
                io_.send_data(ciphertexts.data(),ciphertexts.size());
            } else {
                io_.recv_data(ciphertexts.data(),ciphertexts.size());
                pad_workers_.run(size_t(kBatchBits/8),
                    [raw_pointer,hash_input,global_begin,mode,&choice_bits,&ciphertexts,&output](size_t lo,size_t hi) {
                    auto local_input = hash_input;
                    for (uint64_t j = uint64_t(lo)*8; j < uint64_t(hi)*8; ++j) {
                        const uint8_t e0=bit(ciphertexts,2*j),e1=bit(ciphertexts,2*j+1);
                        const uint8_t choice=bit(choice_bits,j);
                        const uint8_t selected=uint8_t(e0^((e0^e1)&choice));
                        const uint8_t h=pad(local_input,global_begin+j,raw_pointer[size_t(j)],mode);
                        put_bit(output,j,uint8_t(selected^h));
                    }
                });
            }
        }, hook);

        if (observer_) {
            Bytes encoded_raw(size_t(kBatchBits) * 16, 0);
            for (uint64_t j = 0; j < kBatchBits; ++j) {
                const auto bytes = canonical_block(raw[size_t(j)]);
                std::copy(bytes.begin(), bytes.end(), encoded_raw.begin() + size_t(j) * 16);
            }
            Bytes delta;
            if (sender) {
                const auto bytes = canonical_block(core_[d]->Delta);
                delta.assign(bytes.begin(), bytes.end());
            }
            const TransferObservation view{
                party_, direction, sender, global_begin, kBatchBits,
                binding_, sid_, nonce_p0_, nonce_p1_, delta, encoded_raw,
                messages0, messages1, choice_bits, ciphertexts, output};
            observer_(view);
            require(!control_->poisoned, "standard bit OT observer poisoned adapter");
        }
        next_[d] = global_end;
        next_direction_ = 1 - direction;
        operation.finish();
        return output;
    }

    const std::array<uint8_t, 32>& sid() const {
        require(initialized_, "standard bit OT SID unavailable before initialize");
        return sid_;
    }
    bool initialized() const noexcept { return initialized_; }
    bool poisoned() const noexcept { return control_->poisoned; }
    std::array<uint64_t, 2> direction_cursors() const noexcept { return next_; }
};

} // namespace ulim_standard_ot
