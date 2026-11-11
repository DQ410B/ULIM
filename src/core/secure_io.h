#pragma once
#include "src/core/coverage_core.h"
#include "src/core/local_ring.h"
#include <openssl/rand.h>
#include <climits>

namespace ulim_io {
using ulim_local::Big;using ulim_local::Poly;
inline size_t checked_product(size_t a,size_t b,size_t cap=INT_MAX){if(b && a>cap/b)throw std::runtime_error("public allocation/EMP input limit");return a*b;}
inline std::vector<unsigned char> random_bytes(size_t n){if(n>INT_MAX)throw std::runtime_error("RNG request too long");std::vector<unsigned char> b(n);if(n)ulim_local::ok(RAND_priv_bytes(b.data(),int(n)));return b;}
inline Poly uniform_poly(int d,const Big& Q){Poly out(d);for(auto& x:out)ulim_local::ok(BN_priv_rand_range(x.p,Q.p));return out;}
inline Bits private_bits(const std::vector<unsigned char>& bytes,size_t count,int owner){
 if(count>INT_MAX||count>bytes.size()*8)throw std::runtime_error("private bit input length");
 std::unique_ptr<bool[]> b(new bool[count]);std::vector<block> labels(count);
 for(size_t i=0;i<count;++i)b[i]=(bytes[i/8]>>(i%8))&1;
 ProtocolExecution::prot_exec->feed(labels.data(),owner,b.get(),int(count));
 Bits out(count);for(size_t i=0;i<count;++i)out[i].bit=labels[i];return out;
}
inline std::vector<Integer> private_integers(const Poly& local,int width,int owner){
 if(width<1)throw std::runtime_error("zero width");size_t count=checked_product(local.size(),width);
 std::unique_ptr<bool[]> bits(new bool[count]);std::vector<block> labels(count);
 for(size_t i=0;i<local.size();++i)for(int b=0;b<width;++b)bits[i*width+b]=BN_is_bit_set(local[i].p,b);
 ProtocolExecution::prot_exec->feed(labels.data(),owner,bits.get(),int(count));
 std::vector<Integer> out;out.reserve(local.size());
 for(size_t i=0;i<local.size();++i){Bits x(width);for(int b=0;b<width;++b)x[b].bit=labels[i*width+b];out.emplace_back(x);}return out;
}
inline Poly private_open(const std::vector<Integer>& values,int recipient,int party,int width){
 if(width<1)throw std::runtime_error("zero output width");size_t count=checked_product(values.size(),width);
 std::vector<block> labels(count);std::unique_ptr<bool[]> bits(new bool[count]());
 for(size_t i=0;i<values.size();++i){if(values[i].size()<size_t(width))throw std::runtime_error("short output");for(int b=0;b<width;++b)labels[i*width+b]=values[i].bits[b].bit;}
 ProtocolExecution::prot_exec->reveal(bits.get(),recipient,labels.data(),int(count));
 Poly out(values.size());if(party==recipient)for(size_t i=0;i<out.size();++i)for(int b=0;b<width;++b)if(bits[i*width+b])ulim_local::ok(BN_set_bit(out[i].p,b));return out;
}
inline std::vector<unsigned char> exchange(const std::vector<unsigned char>& own,int party,NetIO& io){
 if(own.size()>INT_MAX)throw std::runtime_error("public packet too long");std::vector<unsigned char> other(own.size());
 if(party==ALICE){io.send_data(own.data(),int(own.size()));io.flush();io.recv_data(other.data(),int(other.size()));}
 else{io.recv_data(other.data(),int(other.size()));io.send_data(own.data(),int(own.size()));io.flush();}return other;
}
inline std::vector<unsigned char> serialize(const Poly& p,const Big& Q){
 int width=(Q.bits()+7)/8;std::vector<unsigned char> bytes(checked_product(p.size(),width));
 for(size_t i=0;i<p.size();++i){if(BN_is_negative(p[i].p)||BN_cmp(p[i].p,Q.p)>=0)throw std::runtime_error("noncanonical coefficient");
  if(BN_bn2binpad(p[i].p,bytes.data()+i*width,width)!=width)throw std::runtime_error("serialize coefficient");}return bytes;
}
inline Poly deserialize(const std::vector<unsigned char>& b,size_t count,const Big& Q){
 int width=(Q.bits()+7)/8;if(b.size()!=checked_product(count,width))throw std::runtime_error("packet size");Poly out(count);
 for(size_t i=0;i<count;++i){if(!BN_bin2bn(b.data()+i*width,width,out[i].p))throw std::runtime_error("deserialize coefficient");if(BN_cmp(out[i].p,Q.p)>=0)throw std::runtime_error("peer noncanonical coefficient");}return out;
}
inline Poly exchange_poly(const Poly& own,const Big& Q,int party,NetIO& io){return deserialize(exchange(serialize(own,Q),party,io),own.size(),Q);}
inline Poly negative(const Poly& a,const Big& Q){Poly out(a.size());auto c=ulim_local::context();Big zero;for(size_t i=0;i<a.size();++i)ulim_local::ok(BN_mod_sub(out[i].p,zero.p,a[i].p,Q.p,c.get()));return out;}
inline Poly embed_small(const std::vector<int>& small,const Big& Q){Poly out;out.reserve(small.size());auto c=ulim_local::context();Big zero;
 for(int x:small){Big v(uint64_t(x<0?-x:x));if(x<0)ulim_local::ok(BN_mod_sub(v.p,zero.p,v.p,Q.p,c.get()));out.push_back(std::move(v));}return out;}
}
