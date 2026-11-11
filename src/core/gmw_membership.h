#pragma once
// Standard semi-honest Boolean sharing (ABY III-B): two random OTs per
// multiplication triple, balanced OR, then optional Boolean-to-Yao conversion.
// New isolated profile. No HE key, public-seed state or SH2PC internal OT used.
#include "src/core/secure_io.h"
#include <emp-ot/emp-ot.h>
#include <algorithm>
#include <cstdint>
#include <limits>

namespace ulim_gmw {
using ulim_local::Big;
using ulim_local::Poly;
using LocalBits=std::vector<uint8_t>;

inline void add_count(uint64_t& counter,uint64_t amount) {
    if(amount>std::numeric_limits<uint64_t>::max()-counter)
        throw std::runtime_error("GMW public counter overflow");
    counter+=amount;
}
inline size_t padded_rot_count(size_t logical) {
    if(!logical || logical>size_t(INT_MAX)-7)
        throw std::runtime_error("GMW ROT public length");
    const size_t wire=((logical+7)/8)*8;
    if(wire>size_t(INT_MAX))throw std::runtime_error("GMW padded ROT length");
    return wire;
}
inline size_t packed_bytes(size_t bits) {
    if(bits>size_t(INT_MAX)*8ULL-7)
        throw std::runtime_error("GMW public packed packet limit");
    return (bits+7)/8;
}
inline uint8_t bit_at(const std::vector<unsigned char>& bytes,size_t bit) {
    return uint8_t((bytes.at(bit/8)>>(bit%8))&1U);
}
inline void put_bit(std::vector<unsigned char>& bytes,size_t bit,uint8_t value) {
    if(value>1)throw std::runtime_error("GMW non-bit local value");
    const auto mask=static_cast<unsigned char>(1U<<(bit%8));
    auto& x=bytes.at(bit/8);
    x=static_cast<unsigned char>((x&static_cast<unsigned char>(~mask)) |
                               (value?mask:0));
}

struct Triple { uint8_t a,b,c; };
// Local-only pure kernels exposed for known-fixture algebra tests. s0,s1 are
// the LOW BITS OF HASHED ROT OUTPUTS, not the raw fixed-Delta COT low bits.
inline Triple triple_from_rot(uint8_t s0,uint8_t s1,uint8_t choice,uint8_t received) {
    if((s0|s1|choice|received)>1)throw std::runtime_error("GMW ROT bit encoding");
    const uint8_t a=s0^s1;
    return {a,choice,uint8_t((a&choice)^s0^received)};
}
inline uint8_t or_share(uint8_t x,uint8_t y,const Triple& t,
                        uint8_t e,uint8_t f,int party) {
    if(party!=ALICE && party!=BOB)throw std::runtime_error("GMW OR role");
    if((x|y|t.a|t.b|t.c|e|f)>1)throw std::runtime_error("GMW OR bit encoding");
    const uint8_t product=t.c^(e&t.b)^(f&t.a)^uint8_t(party==BOB?(e&f):0);
    return uint8_t(x^y^product);
}

struct LayerRecord {
    // All shapes are public. sent_bytes is THIS PARTY'S contribution.
    uint64_t batch=0,level=0,width=0,gates=0,packet_bytes=0,sent_bytes=0;
    double ms=0;
    uint64_t yao_ands=0;
};
struct Meters {
    Meter setup,preprocess,online,b2y;
    uint64_t setup_bytes=0,preprocess_bytes=0,online_bytes=0,b2y_bytes=0;
    uint64_t logical_rot=0,wire_rot=0,preprocess_calls=0,batches=0;
    uint64_t gmw_gates=0,online_layers=0;
    uint64_t setup_instances=0,b2y_calls=0,b2y_bits=0;
    std::vector<LayerRecord> layers;
    uint64_t total_bytes()const{return setup_bytes+preprocess_bytes+online_bytes+b2y_bytes;}
    double total_ms()const{return setup.ms+preprocess.ms+online.ms+b2y.ms;}
    // GMW local products are separate from Yao half-gates. All four stages
    // below must consume zero Yao ANDs in this primitive.
    uint64_t yao_ands()const{return setup.ands+preprocess.ands+online.ands+b2y.ands;}
};

class Session {
    int party_;
    NetIO& io_;
    Meters& meters_;
    emp::IKNP<NetIO> forward_,reverse_;

    // Generate all fresh triples for ONE public membership batch. Gate order:
    // increasing tree layer, then coordinate-major, then adjacent-pair-major.
    std::vector<Triple> triples(size_t logical) {
        const size_t wire=padded_rot_count(logical);
        std::vector<Triple> result(logical);
        const auto before=io_.counter;
        meters_.preprocess.run([&]{
            // Each party is receiver in exactly one direction. Logical
            // choices are independent RAND_priv_bytes bits; dummy=false.
            auto randomness=ulim_io::random_bytes(packed_bytes(logical));
            std::unique_ptr<bool[]> choices(new bool[wire]());
            for(size_t i=0;i<logical;++i)choices[i]=bit_at(randomness,i)!=0;
            std::vector<block> send0(wire,zero_block),send1(wire,zero_block);
            std::vector<block> received(wire,zero_block);
            io_.flush();
            if(party_==ALICE)forward_.send_rot(send0.data(),send1.data(),int64_t(wire));
            else forward_.recv_rot(received.data(),choices.get(),int64_t(wire));
            io_.flush();
            if(party_==BOB)reverse_.send_rot(send0.data(),send1.data(),int64_t(wire));
            else reverse_.recv_rot(received.data(),choices.get(),int64_t(wire));
            io_.flush();
            for(size_t i=0;i<logical;++i)
                result[i]=triple_from_rot(uint8_t(getLSB(send0[i])),uint8_t(getLSB(send1[i])),
                                          uint8_t(choices[i]),uint8_t(getLSB(received[i])));
        });
        add_count(meters_.preprocess_bytes,io_.counter-before);
        add_count(meters_.logical_rot,2*uint64_t(logical));
        add_count(meters_.wire_rot,2*uint64_t(wire));
        add_count(meters_.preprocess_calls,2);
        return result;
    }
public:
    // Construct AFTER setup_semi_honest, once per fresh overall session.
    // Caller agrees all public shapes/profile before entering any helper.
    Session(int party,NetIO& io,Meters& meters)
        :party_(party),io_(io),meters_(meters),forward_(&io,false),reverse_(&io,false) {
        if(party!=ALICE && party!=BOB)throw std::runtime_error("GMW session role");
        const auto before=io_.counter;
        meters_.setup.run([&]{
            io_.flush();
            if(party_==ALICE)forward_.setup_send();else forward_.setup_recv();
            io_.flush();
            if(party_==BOB)reverse_.setup_send();else reverse_.setup_recv();
            io_.flush();
        });
        add_count(meters_.setup_bytes,io_.counter-before);
        add_count(meters_.setup_instances,2);
    }
    Session(const Session&)=delete;
    Session& operator=(const Session&)=delete;
    void require_context(int party,NetIO& io)const {
        if(party!=party_ || &io!=&io_)throw std::runtime_error("GMW role/IO mismatch");
    }

    LocalBits membership_xor(const Poly& local_slots,uint32_t q,
                            int n,int len,int repetitions) {
        if(q<3 || !(q&1U) || n<1 || len<1 || repetitions<1)
            throw std::runtime_error("GMW membership public scalar dimensions");
        const size_t coordinates=ulim_io::checked_product(size_t(n),size_t(len));
        const size_t slots=ulim_io::checked_product(coordinates,size_t(repetitions));
        const size_t bitwidth=size_t(bits_for(q));
        const size_t width=ulim_io::checked_product(size_t(repetitions),bitwidth);
        const size_t total_bits=ulim_io::checked_product(coordinates,width);
        const size_t gates=ulim_io::checked_product(coordinates,width-1);
        (void)padded_rot_count(gates);
        if(local_slots.size()!=slots)throw std::runtime_error("GMW local slot count");
        // Public-q validation never reduces or negates an owner slot. In
        // particular Bob's CRT output is already (-b) mod q at this boundary.
        const Big modulus(q);
        for(const auto& x:local_slots)
            if(BN_is_negative(x.p) || BN_cmp(x.p,modulus.p)>=0)
                throw std::runtime_error("GMW noncanonical local slot");
        const uint64_t batch=meters_.batches;
        auto pool=triples(gates);
        LocalBits state;
        const auto before=io_.counter;
        meters_.online.run([&]{
            state.resize(total_bits);
            for(size_t coordinate=0;coordinate<coordinates;++coordinate)
                for(size_t h=0;h<size_t(repetitions);++h)
                    for(size_t bit=0;bit<bitwidth;++bit)
                        state[coordinate*width+h*bitwidth+bit]=
                            uint8_t(BN_is_bit_set(local_slots[coordinate*repetitions+h].p,int(bit)));
            size_t current_width=width,offset=0;uint64_t level=0;
            while(current_width>1) {
                const size_t pairs=current_width/2,next_width=(current_width+1)/2;
                const size_t layer_gates=coordinates*pairs;
                const size_t message_bits=2*layer_gates;
                LayerRecord record;record.batch=batch;record.level=level;
                record.width=current_width;record.gates=layer_gates;
                record.packet_bytes=packed_bytes(message_bits);
                const auto layer_start=Clock::now();
                const auto layer_ands=exact_and_count();
                const auto layer_before=io_.counter;
                std::vector<unsigned char> own(record.packet_bytes,0);
                for(size_t coordinate=0;coordinate<coordinates;++coordinate)
                    for(size_t pair=0;pair<pairs;++pair) {
                        const size_t g=coordinate*pairs+pair;
                        const Triple& t=pool.at(offset+g);
                        const uint8_t x=state[coordinate*current_width+2*pair];
                        const uint8_t y=state[coordinate*current_width+2*pair+1];
                        put_bit(own,2*g,uint8_t(x^t.a));
                        put_bit(own,2*g+1,uint8_t(y^t.b));
                    }
                io_.flush();
                const auto peer=ulim_io::exchange(own,party_,io_);
                io_.flush();
                LocalBits next(coordinates*next_width);
                for(size_t coordinate=0;coordinate<coordinates;++coordinate) {
                    for(size_t pair=0;pair<pairs;++pair) {
                        const size_t g=coordinate*pairs+pair;
                        const uint8_t e=bit_at(own,2*g)^bit_at(peer,2*g);
                        const uint8_t f=bit_at(own,2*g+1)^bit_at(peer,2*g+1);
                        const uint8_t x=state[coordinate*current_width+2*pair];
                        const uint8_t y=state[coordinate*current_width+2*pair+1];
                        next[coordinate*next_width+pair]=or_share(x,y,pool.at(offset+g),e,f,party_);
                    }
                    if(current_width&1U)
                        next[coordinate*next_width+pairs]=state[coordinate*current_width+current_width-1];
                }
                offset+=layer_gates;state=std::move(next);current_width=next_width;
                record.sent_bytes=io_.counter-layer_before;
                record.ms=std::chrono::duration<double,std::milli>(Clock::now()-layer_start).count();
                record.yao_ands=exact_and_count()-layer_ands;
                meters_.layers.push_back(record);
                add_count(meters_.online_layers,1);++level;
            }
            if(offset!=gates || state.size()!=coordinates)
                throw std::runtime_error("GMW balanced tree consumption invariant");
        });
        add_count(meters_.online_bytes,io_.counter-before);
        add_count(meters_.gmw_gates,gates);add_count(meters_.batches,1);
        return state; // Each owner receives ONLY its own XOR shares.
    }

    Bits to_yao(const LocalBits& local_z) {
        if(local_z.empty() || local_z.size()>size_t(INT_MAX))
            throw std::runtime_error("GMW B2Y public count");
        for(auto bit:local_z)if(bit>1)throw std::runtime_error("GMW B2Y non-bit");
        Bits result;
        const auto before=io_.counter;
        meters_.b2y.run([&]{
            io_.flush();
            Poly values;values.reserve(local_z.size());
            for(auto bit:local_z)values.emplace_back(uint64_t(bit));
            const auto a=ulim_io::private_integers(values,1,ALICE);
            const auto b=ulim_io::private_integers(values,1,BOB);
            result.reserve(local_z.size());
            for(size_t i=0;i<local_z.size();++i)result.push_back(a[i].bits[0]^b[i].bits[0]);
            io_.flush();
        });
        add_count(meters_.b2y_bytes,io_.counter-before);
        add_count(meters_.b2y_calls,1);add_count(meters_.b2y_bits,local_z.size());
        return result; // No reveal; the z value remains a secret Yao wire.
    }
};

inline LocalBits membership_xor(const Poly& local_slots,uint32_t q,int n,int len,
        int repetitions,int party,NetIO& io,Session& session) {
    session.require_context(party,io);
    return session.membership_xor(local_slots,q,n,len,repetitions);
}
inline Bits to_yao(const LocalBits& local_z,int party,NetIO& io,Session& session) {
    session.require_context(party,io);return session.to_yao(local_z);
}
inline Bits membership_yao(const Poly& local_slots,uint32_t q,int n,int len,
        int repetitions,int party,NetIO& io,Session& session) {
    return to_yao(membership_xor(local_slots,q,n,len,repetitions,party,io,session),party,io,session);
}
} // namespace ulim_gmw
