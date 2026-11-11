#pragma once
// Public allocation metadata only. No cryptography, IO, randomness or graph data.
#include <array>
#include <cstdint>
#include <functional>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace ulim_scaled_ledger {
struct Segment {
 uint64_t request_id=0,batch_id=0,offset=0,length=0,global_begin=0,global_end=0;
 bool discarded=false;
};
enum class Mode { Full, Stream, Benchmark };
using Observer=std::function<void(const Segment&)>;
inline void need(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
inline std::array<uint8_t,56> encode(const Segment& s){
 std::array<uint8_t,56> bytes{};
 const uint64_t words[7]={s.request_id,s.batch_id,s.offset,s.length,s.global_begin,s.global_end,uint64_t(s.discarded)};
 for(unsigned j=0;j<7;++j)for(unsigned b=0;b<8;++b)bytes[j*8+b]=uint8_t(words[j]>>(8*b));
 return bytes;
}

// Observer must consume synchronously and retain bounded state in Stream/Benchmark.
// A throwing observer can have made a partial write. The ledger is then poisoned;
// its accepted prefix is diagnostic only, and no failed run may be accepted/retried.
class Ledger {
 Mode mode_;uint64_t batch_bits_,retention_limit_,count_=0;
 Observer observer_;bool poisoned_=false,appending_=false;Segment last_{};
 std::vector<Segment> retained_;
public:
 Ledger(uint64_t batch_bits,Mode mode,uint64_t retention_limit,Observer observer={})
  :mode_(mode),batch_bits_(batch_bits),retention_limit_(retention_limit),observer_(std::move(observer)){
  need(batch_bits_>0,"ledger batch width");
  need(mode_==Mode::Full||mode_==Mode::Stream||mode_==Mode::Benchmark,"ledger mode");
  if(mode_==Mode::Full)need(retention_limit_>0,"full ledger needs finite retention cap");
  else{need(retention_limit_==0,"bounded ledger cannot retain history");need(bool(observer_),"bounded ledger requires synchronous observer");}
 }
 Ledger(const Ledger&)=delete;Ledger& operator=(const Ledger&)=delete;
 Ledger(Ledger&&)=delete;Ledger& operator=(Ledger&&)=delete;
 void append(const Segment s){
  need(!poisoned_,"ledger poisoned");
  if(appending_){poisoned_=true;need(false,"reentrant ledger append");}
  appending_=true;
  try{
   need(count_<std::numeric_limits<uint64_t>::max(),"segment count overflow");
   need(s.length>0&&s.offset<batch_bits_&&s.length<=batch_bits_-s.offset,"segment batch range");
   need(s.length<=std::numeric_limits<uint64_t>::max()-s.global_begin&&s.global_end==s.global_begin+s.length,"segment global range");
   need(s.batch_id==s.global_begin/batch_bits_&&s.offset==s.global_begin%batch_bits_,"segment address");
   if(count_==0)need(s.global_begin==0&&s.request_id==0,"first segment");
   else{
    need(s.global_begin==last_.global_end,"segment continuity");
    if(s.request_id==last_.request_id){
     need(last_.offset+last_.length==batch_bits_&&s.offset==0,"fragment must cross batch boundary");
     need(s.discarded==last_.discarded,"fragment discard mismatch");
    }else need(last_.request_id<std::numeric_limits<uint64_t>::max()&&s.request_id==last_.request_id+1,"request continuity");
   }
   if(mode_==Mode::Full){need(count_<retention_limit_,"full ledger retention cap");retained_.push_back(s);}
   if(observer_)observer_(s);
   need(!poisoned_,"observer poisoned ledger");
   last_=s;++count_;appending_=false;
  }catch(...){poisoned_=true;appending_=false;throw;}
 }
 uint64_t count()const{return count_;}
 bool poisoned()const{return poisoned_;}
 Mode mode()const{return mode_;}
 uint64_t retained_count()const{return uint64_t(retained_.size());}
 const std::vector<Segment>& retained()const{
  need(mode_==Mode::Full,"history unavailable in bounded mode");
  need(!poisoned_,"poisoned ledger has no accepted full history");return retained_;
 }
};
} // namespace ulim_scaled_ledger
