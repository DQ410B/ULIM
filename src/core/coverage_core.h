#pragma once
// Coverage logic copied from tested v3; the meter now uses exact consumed hash keys.
#include <emp-sh2pc/emp-sh2pc.h>
#include <chrono>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <sys/resource.h>
#include <vector>
#include <string>
#include <iostream>

using namespace emp;
using Clock = std::chrono::steady_clock;
using Bits = std::vector<Bit>;

// Pinned EMP 0.3.0 num_and() counts allocated hash keys in groups of eight,
// hence rounds cumulative AND count up to a multiple of four. Recover the
// consumed count at stage boundaries without changing any gates or upstream.
inline uint64_t exact_and_count() {
    auto* circuit = CircuitExecution::circ_exec;
    if (auto* g = dynamic_cast<HalfGateGen<NetIO>*>(circuit))
        return (g->mitccrh.gid - (8 - g->mitccrh.key_used)) / 2;
    if (auto* e = dynamic_cast<HalfGateEva<NetIO>*>(circuit))
        return (e->mitccrh.gid - (8 - e->mitccrh.key_used)) / 2;
    throw std::runtime_error("exact counter requires pinned HalfGateGen/Eva<NetIO>");
}
struct Meter {
    double ms = 0;
    uint64_t ands = 0;
    template<class F> void run(F f) {
        auto t = Clock::now();
        auto a = exact_and_count();
        f();
        ms += std::chrono::duration<double, std::milli>(Clock::now()-t).count();
        ands += exact_and_count()-a;
    }
};

int bits_for(unsigned x) { int w=0; do { ++w; x >>= 1; } while(x); return w; }

struct Shares {
    std::ifstream in;
    int n, theta;
    std::streampos offset;
    explicit Shares(const std::string& path):in(path, std::ios::binary) {
        if(!in || !(in>>n>>theta) || n<1 || theta<1) throw std::runtime_error("invalid share header");
        if(in.get()!='\n') throw std::runtime_error("expected newline after share header");
        offset=in.tellg();
        in.seekg(0,std::ios::end);
        if(in.tellg()-offset!=int64_t(n)*theta) throw std::runtime_error("wrong share file length");
    }
    std::unique_ptr<bool[]> batch(int start,int len) {
        size_t count=size_t(n)*len;
        if(count>INT_MAX) throw std::runtime_error("EMP input batch exceeds int length");
        std::unique_ptr<bool[]> b(new bool[count]);
        std::vector<unsigned char> row(len);
        for(int v=0;v<n;++v) {
            in.seekg(offset+std::streamoff(int64_t(v)*theta+start));
            in.read(reinterpret_cast<char*>(row.data()),len);
            if(!in) throw std::runtime_error("short share read");
            for(int j=0;j<len;++j) {
                if(row[j]>1) throw std::runtime_error("nonbit share");
                b[size_t(v)*len+j]=row[j];
            }
        }
        return b;
    }
};

Bits input_batch(Shares& shares, int start, int len) {
    auto local=shares.batch(start,len);
    size_t count=size_t(shares.n)*len;
    std::vector<block> a(count),b(count);
    // The non-owner's local array is ignored by EMP's feed implementation.
    ProtocolExecution::prot_exec->feed(a.data(),ALICE,local.get(),int(count));
    ProtocolExecution::prot_exec->feed(b.data(),BOB,local.get(),int(count));
    Bits z(count);
    for(size_t i=0;i<count;++i) { Bit x,y; x.bit=a[i]; y.bit=b[i]; z[i]=x^y; }
    return z;
}

// Public tree shape, increasing widths; O(theta) full-adder work instead of
// theta additions at the final counter width. Every resize zero-extends.
Integer popcount(const Bits& b, int out_width) {
    struct Partial { Integer x; unsigned bound; };
    std::vector<Partial> level;
    level.reserve(b.size());
    for(auto bit:b) level.push_back({Integer(Bits{bit}),1});
    if(level.empty()) return Integer(out_width,0,PUBLIC);
    while(level.size()>1) {
        std::vector<Partial> next;
        next.reserve((level.size()+1)/2);
        for(size_t i=0;i<level.size();i+=2) {
            if(i+1==level.size()) { next.push_back(std::move(level[i])); continue; }
            auto sum_bound=level[i].bound+level[i+1].bound;
            int w=bits_for(sum_bound);
            level[i].x.resize(w,false); level[i+1].x.resize(w,false);
            next.push_back({level[i].x+level[i+1].x,sum_bound});
        }
        level=std::move(next);
    }
    level[0].x.resize(out_width,false);
    return level[0].x;
}

Bits onehot_max(const Bits& selected,const std::vector<Integer>& gains,int width) {
    const int n=int(selected.size());
    int leaves=1; while(leaves<n) leaves*=2;
    Bits eligible(2*leaves,Bit(false,PUBLIC)), choose_right(2*leaves,Bit(false,PUBLIC));
    std::vector<Integer> values(2*leaves,Integer(width,0,PUBLIC));
    for(int v=0;v<n;++v) { eligible[leaves+v]=!selected[v]; values[leaves+v]=gains[v]; }
    for(int v=leaves-1;v>=1;--v) {
        int l=2*v,r=l+1;
        // Top bit is public zero: EMP's signed comparison equals unsigned here.
        Bit t=((!eligible[l])&eligible[r])|((eligible[l]==eligible[r])&(values[r]>values[l]));
        choose_right[v]=t;
        eligible[v]=eligible[l]|eligible[r];
        values[v]=values[l].select(t,values[r]);
    }
    Bits path(2*leaves,Bit(false,PUBLIC)); path[1]=Bit(true,PUBLIC);
    for(int v=1;v<leaves;++v) { path[2*v+1]=path[v]&choose_right[v]; path[2*v]=path[v]^path[2*v+1]; }
    return Bits(path.begin()+leaves,path.begin()+leaves+n);
}

Bits covered_by(const Bits& z,const Bits& selected,int n,int len) {
    Bits c(len,Bit(false,PUBLIC));
    for(int j=0;j<len;++j) for(int v=0;v<n;++v) c[j]=c[j]|(selected[v]&z[size_t(v)*len+j]);
    return c;
}

std::vector<Integer> marginal(const Bits& z,const Bits& covered,int n,int len,int width) {
    std::vector<Integer> gains;
    gains.reserve(n);
    Bits row(len);
    for(int v=0;v<n;++v) {
        for(int j=0;j<len;++j) row[j]=z[size_t(v)*len+j]&(!covered[j]);
        gains.push_back(popcount(row,width));
    }
    return gains;
}

