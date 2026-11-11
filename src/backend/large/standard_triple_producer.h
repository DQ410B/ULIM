#pragma once
#include "src/core/segment_ledger.h"
#include "src/backend/large/standard_bit_ot.h"
#include <cerrno>
#include <sys/random.h>
#include <unistd.h>
// Source-derived packed pool; cryptography is the separate standard bit-OT adapter.
#include <emp-tool/emp-tool.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <utility>
#include <vector>

namespace ulim_standard_fresh {
using Bytes=std::vector<uint8_t>;
inline constexpr uint64_t kBatchBits=65536;
struct Limits {uint64_t max_batches=3;uint64_t max_take_bits=3*kBatchBits;};
using Binding=std::array<uint8_t,32>;
// Callback views are temporary. The optional diagnostic observer must consume
// synchronously, must not reenter, and must not retain references.
struct PoolObservation {
 uint64_t batch_id,global_begin;
 const Bytes &a,&b,&r,&incoming,&c;
};
using PoolObserver=std::function<void(const PoolObservation&)>;
inline void entropy_bytes(Bytes& out){
 size_t offset=0;
 while(offset<out.size()){
  const size_t count=std::min<size_t>(256,out.size()-offset);
  int rc;do{rc=::getentropy(out.data()+offset,count);}while(rc<0&&errno==EINTR);
  if(rc!=0)throw std::runtime_error("getentropy failed");
  offset+=count;
 }
}
using Segment=ulim_scaled_ledger::Segment;
struct PackedTriples {
 uint64_t bit_count=0;Bytes a,b,c;std::vector<Segment> segments;
};
struct PhaseRecord {
 uint64_t batch_id=0;int direction=-1;std::string name;bool complete=false;
 uint64_t sent_begin=0,received_begin=0,sent_bytes=0,received_bytes=0;double wall_ms=0,cpu_ms=0;
};
struct BatchRecord {
 uint64_t batch_id=0,global_begin=0,global_end=0,bit_count=0;
 bool complete=false;std::string status="running";uint64_t sent_bytes=0;
 double wall_ms=0,cpu_ms=0;std::vector<PhaseRecord> phases;
};
inline void require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
inline uint64_t packed_bytes(uint64_t count){return count/8+(count%8!=0);}
inline uint64_t checked_end(uint64_t begin,uint64_t length){
 require(length<=std::numeric_limits<uint64_t>::max()-begin,"uint64 range overflow");return begin+length;
}
inline size_t allocation_bytes(uint64_t count){
 uint64_t n=packed_bytes(count);require(n<=std::numeric_limits<size_t>::max(),"size_t allocation overflow");
 require(n<=Bytes().max_size(),"vector allocation limit");return static_cast<size_t>(n);
}
inline void copy_bits(Bytes& dst,uint64_t dst_bits,uint64_t to,const Bytes& src,uint64_t src_bits,uint64_t from,uint64_t length){
 require(to<=dst_bits&&length<=dst_bits-to,"destination bit range");
 require(from<=src_bits&&length<=src_bits-from,"source bit range");
 require(packed_bytes(dst_bits)<=dst.size()&&packed_bytes(src_bits)<=src.size(),"codec buffer size");
 // Caller supplies distinct producer/output vectors; arbitrary offsets are supported.
 require(&dst!=&src||length==0,"in-place bit copy is not supported");
 while(length){unsigned db=unsigned(to&7),sb=unsigned(from&7);
  unsigned take=unsigned(std::min<uint64_t>(length,std::min(8-db,8-sb)));
  unsigned mask=(1u<<take)-1u;unsigned value=(src[size_t(from/8)]>>sb)&mask;
  dst[size_t(to/8)]=uint8_t((unsigned(dst[size_t(to/8)])&~(mask<<db))|(value<<db));
  to+=take;from+=take;length-=take;
 }
}
inline void mask_tail(Bytes& value,uint64_t count){
 require(value.size()==packed_bytes(count),"packed output length");
 if(count%8)value.back()&=uint8_t((1u<<unsigned(count%8))-1u);
}

// Synchronous, non-copyable: every instance owns a single live-session cursor.
template<class IO> class FreshTripleProducer {
 using Clock=std::chrono::steady_clock;
 int party_;IO& io_;Limits limits_;
 uint64_t produced_=0,consumed_=0,delivered_=0,discarded_=0,requests_=0;
 bool poisoned_=false,consuming_=false;
 Bytes a_,b_,c_;
 std::vector<BatchRecord> batches_;
 ulim_scaled_ledger::Ledger ledger_;
 ulim_standard_ot::StandardOtBitAdapter<IO> adapter_;
 PoolObserver pool_observer_;
 static double ms(Clock::time_point start){return std::chrono::duration<double,std::milli>(Clock::now()-start).count();}
 static double cpu(){rusage r{};require(getrusage(RUSAGE_SELF,&r)==0,"getrusage");return 1000.0*(r.ru_utime.tv_sec+r.ru_stime.tv_sec)+(r.ru_utime.tv_usec+r.ru_stime.tv_usec)/1000.0;}
 static bool bit(const Bytes& x,uint64_t i){return (x[size_t(i/8)]>>unsigned(i&7))&1u;}
 static void set_one(Bytes& x,uint64_t i,bool value){x[size_t(i/8)]|=uint8_t(unsigned(value)<<unsigned(i&7));}
 template<class F> void phase(BatchRecord& batch,int direction,const std::string& name,F work){
  PhaseRecord rec;rec.batch_id=batch.batch_id;rec.direction=direction;rec.name=name;batch.phases.push_back(rec);
  auto& p=batch.phases.back();auto start=Clock::now();double before_cpu=cpu();uint64_t before=io_.counter;
  p.sent_begin=before;p.received_begin=io_.received;
  auto finish=[&]{require(io_.counter>=before&&io_.received>=p.received_begin,"IO counter decreased");p.sent_bytes=io_.counter-before;p.received_bytes=io_.received-p.received_begin;p.wall_ms=ms(start);p.cpu_ms=cpu()-before_cpu;};
  try{work();io_.flush();p.complete=true;}catch(...){finish();throw;}finish();
 }
 void refill(){
  require(!poisoned_&&consumed_==produced_,"refill with unconsumed batch");
  require(batches_.size()<limits_.max_batches,"batch budget");
  uint64_t end=checked_end(produced_,kBatchBits);
  BatchRecord record;record.batch_id=produced_/kBatchBits;record.global_begin=produced_;record.global_end=end;batches_.push_back(record);
  auto& batch=batches_.back();auto start=Clock::now();double cstart=cpu();uint64_t before=io_.counter;
  try{
   if(!adapter_.initialized())phase(batch,-1,"session_nonce",[&]{adapter_.initialize();});
   Bytes r(kBatchBits/8),m1(kBatchBits/8),incoming;
   phase(batch,-1,"local_triple_coins",[&]{
    a_.assign(kBatchBits/8,0);b_.assign(kBatchBits/8,0);c_.assign(kBatchBits/8,0);
    entropy_bytes(a_);entropy_bytes(b_);entropy_bytes(r);
    for(size_t j=0;j<m1.size();++j)m1[j]=r[j]^a_[j];
   });
   const Bytes empty;
   auto hook=[&](int dir,const std::string& name,const std::function<void()>& work){phase(batch,dir,name,work);};
   for(int dir=0;dir<2;++dir){
    bool sender=party_==dir+1;
    auto result=adapter_.transfer(dir,produced_,sender?r:empty,sender?m1:empty,sender?empty:b_,hook);
    if(!sender)incoming=std::move(result);
    require(!poisoned_,"OT observer poisoned producer");
   }
   phase(batch,-1,"triple_pack",[&]{
    require(incoming.size()==kBatchBits/8,"incoming OT output shape");
    for(size_t j=0;j<c_.size();++j)c_[j]=(a_[j]&b_[j])^r[j]^incoming[j];
    if(pool_observer_)pool_observer_(PoolObservation{batch.batch_id,produced_,a_,b_,r,incoming,c_});
    require(!poisoned_,"pool observer poisoned producer");
   });
   produced_=end;batch.bit_count=kBatchBits;batch.complete=true;batch.status="pass";
  }catch(...){poisoned_=true;batch.status="failed";batch.sent_bytes=io_.counter-before;batch.wall_ms=ms(start);batch.cpu_ms=cpu()-cstart;throw;}
  batch.sent_bytes=io_.counter-before;batch.wall_ms=ms(start);batch.cpu_ms=cpu()-cstart;
 }
 void precheck(uint64_t count,bool drop){
  if(consuming_){poisoned_=true;require(false,"reentrant producer request");}
  require(!poisoned_,"producer poisoned after failure");
  (void)checked_end(consumed_,count);
  require(count<=limits_.max_batches*kBatchBits-consumed_,"public total batch budget");
  require(count<=(drop?std::numeric_limits<uint64_t>::max()-discarded_:std::numeric_limits<uint64_t>::max()-delivered_),"accounting overflow");
  if(count)require(requests_<std::numeric_limits<uint64_t>::max(),"request ID overflow");
  require(count<=limits_.max_take_bits,"single request bit budget");
  if(!drop)(void)allocation_bytes(count);
 }
 void consume(uint64_t count,bool drop,PackedTriples* out){
  if(count==0)return;
  consuming_=true;uint64_t request=requests_++;uint64_t done=0;
  try{
   while(done<count){if(consumed_==produced_)refill();
    uint64_t offset=consumed_%kBatchBits;uint64_t length=std::min(count-done,produced_-consumed_);
    Segment s{request,consumed_/kBatchBits,offset,length,consumed_,checked_end(consumed_,length),drop};
    if(!drop){copy_bits(out->a,count,done,a_,kBatchBits,offset,length);copy_bits(out->b,count,done,b_,kBatchBits,offset,length);copy_bits(out->c,count,done,c_,kBatchBits,offset,length);out->segments.push_back(s);}
    ledger_.append(s);require(!poisoned_,"observer poisoned producer");consumed_=s.global_end;done+=length;
    if(drop)discarded_+=length;else delivered_+=length;
   }
   consuming_=false;
  }catch(...){poisoned_=true;consuming_=false;throw;}
 }
public:
 explicit FreshTripleProducer(int party,IO& io,const Binding& agreed_binding,Limits limits,
  ulim_scaled_ledger::Mode mode,uint64_t retention_limit,ulim_scaled_ledger::Observer observer={},
  typename ulim_standard_ot::StandardOtBitAdapter<IO>::Observer ot_observer={},PoolObserver pool_observer={})
  :party_(party),io_(io),limits_(limits),ledger_(kBatchBits,mode,retention_limit,std::move(observer)),
   adapter_(party,io,agreed_binding),pool_observer_(std::move(pool_observer)){
  require(party==1||party==2,"party");
  require(limits.max_batches>0&&limits.max_batches<=std::numeric_limits<uint64_t>::max()/kBatchBits,"batch budget overflow");
  require(limits.max_take_bits>0&&limits.max_take_bits<=limits.max_batches*kBatchBits,"single request bit budget");
  (void)allocation_bytes(limits.max_take_bits);
  adapter_.set_observer(std::move(ot_observer));
 }
 FreshTripleProducer(const FreshTripleProducer&)=delete;
 FreshTripleProducer& operator=(const FreshTripleProducer&)=delete;
 FreshTripleProducer(FreshTripleProducer&&)=delete;
 FreshTripleProducer& operator=(FreshTripleProducer&&)=delete;
 PackedTriples take(uint64_t count){
  precheck(count,false);PackedTriples result;result.bit_count=count;
  size_t bytes=allocation_bytes(count);result.a.assign(bytes,0);result.b.assign(bytes,0);result.c.assign(bytes,0);
  consume(count,false,&result);mask_tail(result.a,count);mask_tail(result.b,count);mask_tail(result.c,count);return result;
 }
 void discard(uint64_t count){precheck(count,true);consume(count,true,nullptr);}
 uint64_t produced()const{return produced_;}
 uint64_t consumed()const{return consumed_;}
 uint64_t global_cursor()const{return consumed_;}
 uint64_t delivered()const{return delivered_;}
 uint64_t discarded()const{return discarded_;}
 uint64_t remaining()const{return produced_-consumed_;}
 uint64_t unused()const{return remaining();}
 uint64_t completed_batches()const{return produced_/kBatchBits;}
 bool poisoned()const{return poisoned_||adapter_.poisoned();}
 const Limits& limits()const{return limits_;}
 const std::vector<BatchRecord>& batches()const{return batches_;}
 uint64_t next_request_id()const{return requests_;}
 uint64_t segment_count()const{return ledger_.count();}
 uint64_t retained_segment_count()const{return ledger_.retained_count();}
 const std::vector<Segment>& segments()const{return ledger_.retained();}
 std::vector<PhaseRecord> phase_records()const{std::vector<PhaseRecord> result;for(const auto& b:batches_)result.insert(result.end(),b.phases.begin(),b.phases.end());return result;}
};
} // namespace ulim_standard_fresh
