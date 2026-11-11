#pragma once
#include <openssl/bn.h>
#include <algorithm>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace ulim_local {
inline void ok(int x) { if(x!=1) throw std::runtime_error("OpenSSL BN operation failed"); }
struct Big {
    BIGNUM* p;
    Big():p(BN_new()) { if(!p)throw std::bad_alloc(); BN_zero(p); }
    explicit Big(uint64_t v):Big() { ok(BN_set_word(p,v)); }
    explicit Big(const std::string& s):Big() {
        if(s.empty()||s.find_first_not_of("0123456789")!=std::string::npos)
            throw std::runtime_error("expected unsigned decimal integer");
        if(BN_dec2bn(&p,s.c_str())==0)throw std::runtime_error("invalid decimal integer");
    }
    Big(const Big& b):Big() { if(!BN_copy(p,b.p))throw std::bad_alloc(); }
    Big(Big&& b) noexcept:p(b.p) {b.p=nullptr;}
    Big& operator=(const Big& b) {if(this!=&b && !BN_copy(p,b.p))throw std::bad_alloc();return *this;}
    Big& operator=(Big&& b) noexcept {if(this!=&b){BN_clear_free(p);p=b.p;b.p=nullptr;}return *this;}
    ~Big(){BN_clear_free(p);}
    std::string str() const {char* s=BN_bn2dec(p);if(!s)throw std::bad_alloc();std::string r(s);OPENSSL_free(s);return r;}
    int bits() const {return BN_num_bits(p);}
};
using Poly=std::vector<Big>;
using Context=std::unique_ptr<BN_CTX,decltype(&BN_CTX_free)>;
inline Context context(){Context c(BN_CTX_new(),BN_CTX_free);if(!c)throw std::bad_alloc();return c;}
inline uint32_t powmod(uint32_t a,uint64_t e,uint32_t p){
    uint64_t v=1,x=a;for(;e;e>>=1,x=x*x%p)if(e&1)v=v*x%p;return uint32_t(v);
}
inline bool prime32(uint32_t p){
    if(p<2)return false;for(uint64_t x=2;x*x<=p;++x)if(p%x==0)return false;return true;
}
inline uint32_t root2d(uint32_t p,int d){
    if(d<1||(d&(d-1))||!prime32(p)||(uint64_t(p)-1)%(2ULL*d))
        throw std::runtime_error("NTT requires a prime 1 mod 2d and power-of-two d");
    for(uint32_t x=2;x<p;++x){auto r=powmod(x,(p-1)/(2*d),p);if(powmod(r,d,p)==p-1)return r;}
    throw std::runtime_error("primitive root not found");
}
inline void ntt(std::vector<uint32_t>& a,uint32_t omega,uint32_t p,bool inverse){
    size_t n=a.size();
    for(size_t i=1,j=0;i<n;++i){size_t b=n>>1;for(;j&b;b>>=1)j^=b;j^=b;if(i<j)std::swap(a[i],a[j]);}
    if(inverse)omega=powmod(omega,p-2,p);
    for(size_t len=2;len<=n;len<<=1){
        uint32_t wl=powmod(omega,n/len,p);
        for(size_t start=0;start<n;start+=len){uint64_t w=1;
            for(size_t j=0;j<len/2;++j){uint32_t u=a[start+j],v=w*a[start+j+len/2]%p;
                a[start+j]=(uint64_t(u)+v)%p;
                a[start+j+len/2]=(uint64_t(u)+p-v)%p;w=w*wl%p;
            }
        }
    }
    if(inverse){uint32_t inv=powmod(uint32_t(n),p-2,p);for(auto& x:a)x=uint64_t(x)*inv%p;}
}
inline std::vector<uint32_t> transform(std::vector<uint32_t> a,uint32_t psi,uint32_t p,bool inverse){
    if(!inverse){uint64_t w=1;for(auto& x:a){x=x*w%p;w=w*psi%p;}ntt(a,uint64_t(psi)*psi%p,p,false);}
    else {ntt(a,uint64_t(psi)*psi%p,p,true);uint64_t w=1,ip=powmod(psi,p-2,p);for(auto& x:a){x=x*w%p;w=w*ip%p;}}
    return a;
}

class Ring {
    std::vector<uint32_t> factors_,roots_;
    std::vector<Big> crt_;
public:
    int d; uint32_t q,psi_q; Big delta,Q;
    Ring(int dim,uint32_t plain,const std::string& scale,const std::vector<uint32_t>& factors)
        :factors_(factors),d(dim),q(plain),psi_q(root2d(plain,dim)),delta(scale),Q(){
        auto c=context();Big bq(q);ok(BN_mul(Q.p,delta.p,bq.p,c.get()));
        if(BN_is_zero(delta.p))throw std::runtime_error("delta must be positive");
        if(!factors_.empty()){
            Big product(1);for(auto p:factors_){if(p>0x7fffffffU)throw std::runtime_error("RNS factor exceeds 31 bits");
                roots_.push_back(root2d(p,d));Big bp(p),next;ok(BN_mul(next.p,product.p,bp.p,c.get()));product=std::move(next);}
            if(BN_cmp(product.p,Q.p))throw std::runtime_error("RNS factor product is not Q");
            for(auto p:factors_){Big quotient,bp(p),r;ok(BN_div(quotient.p,r.p,Q.p,bp.p,c.get()));
                auto mod=BN_mod_word(quotient.p,p);if(mod==static_cast<BN_ULONG>(-1)||mod==0)throw std::runtime_error("noncoprime RNS factors");
                ok(BN_mul_word(quotient.p,powmod(mod,p-2,p)));crt_.push_back(std::move(quotient));}
        }
    }
    Poly add(const Poly& a,const Poly& b) const {
        Poly r(d);auto c=context();for(int i=0;i<d;++i)ok(BN_mod_add(r[i].p,a[i].p,b[i].p,Q.p,c.get()));return r;
    }
    Poly multiply_naive(const Poly& a,const Poly& b) const {
        Poly r(d);auto c=context();Big t;
        for(int i=0;i<d;++i)for(int j=0;j<d;++j){ok(BN_mod_mul(t.p,a[i].p,b[j].p,Q.p,c.get()));
            int k=(i+j)%d;if(i+j<d)ok(BN_mod_add(r[k].p,r[k].p,t.p,Q.p,c.get()));
            else ok(BN_mod_sub(r[k].p,r[k].p,t.p,Q.p,c.get()));}
        return r;
    }
    Poly multiply(const Poly& a,const Poly& b) const {
        if(a.size()!=size_t(d)||b.size()!=size_t(d))throw std::runtime_error("wrong polynomial length");
        if(factors_.empty())return multiply_naive(a,b);
        std::vector<std::vector<uint32_t>> residues;
        for(size_t f=0;f<factors_.size();++f){uint32_t p=factors_[f];std::vector<uint32_t>x(d),y(d);
            for(int i=0;i<d;++i){x[i]=BN_mod_word(a[i].p,p);y[i]=BN_mod_word(b[i].p,p);}
            x=transform(std::move(x),roots_[f],p,false);y=transform(std::move(y),roots_[f],p,false);
            for(int i=0;i<d;++i)x[i]=uint64_t(x[i])*y[i]%p;
            residues.push_back(transform(std::move(x),roots_[f],p,true));
        }
        Poly r(d);Big t;auto c=context();
        for(int i=0;i<d;++i){for(size_t f=0;f<factors_.size();++f){
            if(!BN_copy(t.p,crt_[f].p))throw std::bad_alloc();ok(BN_mul_word(t.p,residues[f][i]));ok(BN_add(r[i].p,r[i].p,t.p));}
            ok(BN_nnmod(r[i].p,r[i].p,Q.p,c.get()));}
        return r;
    }
    std::vector<uint32_t> decode(const std::vector<uint32_t>& coeff) const {
        if(coeff.size()!=size_t(d))throw std::runtime_error("wrong CRT input size");
        return transform(coeff,psi_q,q,false);
    }
    bool uses_ntt() const {return !factors_.empty();}
};
}
