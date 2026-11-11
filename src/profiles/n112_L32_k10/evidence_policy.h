#pragma once
// Local evidence only. This class never owns or calls a transport or producer.
namespace matched_s_evidence {
using Bytes=std::vector<unsigned char>;
using Rows=std::vector<Bytes>;
inline void require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
inline void u32(Bytes& out,uint32_t x){for(unsigned i=0;i<4;++i)out.push_back(static_cast<unsigned char>(x>>(8*i)));}
inline void u64(Bytes& out,uint64_t x){for(unsigned i=0;i<8;++i)out.push_back(static_cast<unsigned char>(x>>(8*i)));}
inline size_t packed(uint64_t bits){require(bits<=UINT64_MAX-7,"evidence bit width overflow");return size_t((bits+7)/8);}
inline std::string digest(const SHA256_CTX& source){auto copy=source;unsigned char out[32];require(SHA256_Final(out,&copy)==1,"evidence SHA256 final");std::ostringstream s;s<<std::hex<<std::setfill('0');for(auto c:out)s<<std::setw(2)<<unsigned(c);return s.str();}

class EvidencePolicy {
 bool configured_=false,benchmark_=false,ledger_initialized_=false;
 uint32_t party_=0,n_=0,L_=0,k_=0,ell_=0,w_=0,mode_code_=0;
 SHA256_CTX ledger_hash_{},semantic_hash_{};
 uint64_t ledger_records_=0,semantic_records_=0,semantic_bytes_=0;
 Bytes buffered_;std::string buffered_path_;bool buffer_sealed_=false,buffer_success_=false;
 int fd_=-1;bool semantic_initialized_=false,semantic_closed_=false,semantic_complete_=false,semantic_failed_=false;
 void write(const void* data,size_t count){
  if(benchmark_){require(semantic_initialized_&&!buffer_sealed_&&!semantic_failed_,"semantic memory writable");
   require(count<=13486-buffered_.size(),"matched semantic memory cap");const auto* p=static_cast<const unsigned char*>(data);
   buffered_.insert(buffered_.end(),p,p+count);semantic_bytes_+=count;
   require(SHA256_Update(&semantic_hash_,p,count)==1,"semantic memory SHA256 update");return;}

  require(fd_>=0&&!semantic_failed_,"semantic stream writable");const auto* p=static_cast<const unsigned char*>(data);
  try{while(count){ssize_t used=::write(fd_,p,count);if(used<0&&errno==EINTR)continue;require(used>0,"semantic stream write");
    semantic_bytes_+=uint64_t(used);require(SHA256_Update(&semantic_hash_,p,size_t(used))==1,"semantic SHA256 update");p+=used;count-=size_t(used);
  }}catch(...){semantic_failed_=true;throw;}
 }
 void expected(uint32_t& tag,uint32_t& ordinal,uint32_t& rows,uint32_t& width)const{
  require(semantic_records_<uint64_t(2)*k_+4,"semantic record count cap");rows=1;
  if(semantic_records_==0){tag=1;ordinal=0;rows=L_;width=n_*ell_;return;}
  if(semantic_records_<=uint64_t(2)*k_){uint64_t i=semantic_records_-1;tag=(i%2)?3:2;ordinal=uint32_t(i/2);width=tag==2?2*n_*w_+n_:2*n_;return;}
  tag=uint32_t(semantic_records_-2*k_+3);ordinal=k_;width=n_;
 }
public:
 EvidencePolicy()=default;EvidencePolicy(const EvidencePolicy&)=delete;EvidencePolicy& operator=(const EvidencePolicy&)=delete;
 ~EvidencePolicy(){if(fd_>=0)::close(fd_);}
 void configure(const std::string& mode,uint32_t party,uint32_t n,uint32_t L,uint32_t k,uint32_t ell,uint32_t w){
  require(!configured_,"evidence configured once");require(mode=="full"||mode=="stream"||mode=="benchmark","evidence mode");
  require((party==1||party==2)&&n==112&&L==32&&k==10&&ell==7&&w==33,"exact supplementary D evidence profile");
  party_=party;n_=n;L_=L;k_=k;ell_=ell;w_=w;benchmark_=mode=="benchmark";mode_code_=mode=="full"?0:(mode=="stream"?1:2);
  require(SHA256_Init(&ledger_hash_)==1,"ledger evidence SHA256 init");ledger_initialized_=true;configured_=true;
 }
 bool benchmark()const{return benchmark_;}
 bool capture_gate_material()const{return !benchmark_;}
 uint32_t mode_code()const{return mode_code_;}
 ulim_scaled_ledger::Mode producer_mode()const{return mode_code_==0?ulim_scaled_ledger::Mode::Full:(mode_code_==1?ulim_scaled_ledger::Mode::Stream:ulim_scaled_ledger::Mode::Benchmark);}
 void on_segment(const ulim_scaled_ledger::Segment& segment){
  require(configured_&&ledger_initialized_,"ledger evidence configured");require(ledger_records_<20466ULL,"ledger evidence finite record cap");
  const auto raw=ulim_scaled_ledger::encode(segment);require(SHA256_Update(&ledger_hash_,raw.data(),raw.size())==1,"ledger evidence SHA256 update");++ledger_records_;
 }
 uint64_t ledger_records_observed()const{return ledger_records_;}
 std::string ledger_records_sha256()const{return ledger_initialized_?digest(ledger_hash_):"";}
 void open_semantics(const std::string& path,const Bytes& app_binding){
  require(configured_&&fd_<0&&!semantic_initialized_&&app_binding.size()==32,"semantic stream opens once");
  require(SHA256_Init(&semantic_hash_)==1,"semantic SHA256 init");semantic_initialized_=true;
  if(benchmark_){buffered_path_=path;buffered_.reserve(13486);}else{fd_=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);require(fd_>=0,"exclusive semantic stream create");}
  Bytes header={'U','L','S','E','M','0','0','1'};for(uint32_t x:{1u,party_,n_,L_,k_,ell_,w_,0u})u32(header,x);
  header.insert(header.end(),app_binding.begin(),app_binding.end());require(header.size()==72,"semantic header ABI");write(header.data(),header.size());
 }
 void record(uint32_t tag,uint32_t ordinal,uint32_t width,const Rows& values){
  require(configured_&&!semantic_complete_&&!semantic_closed_,"semantic record state");uint32_t wanted_tag,wanted_ordinal,wanted_rows,wanted_width;expected(wanted_tag,wanted_ordinal,wanted_rows,wanted_width);
  require(tag==wanted_tag&&ordinal==wanted_ordinal&&width==wanted_width&&values.size()==wanted_rows,"semantic record public schedule");
  const size_t stride=packed(width);const uint64_t payload=uint64_t(stride)*values.size();require(payload<=3136,"semantic record payload cap");
  for(const auto& row:values){require(row.size()==stride,"semantic row length");if(width%8)require((row.back()>>(width%8))==0,"semantic row tail");}
  Bytes header;u32(header,tag);u32(header,ordinal);u32(header,wanted_rows);u32(header,width);u64(header,payload);require(header.size()==24,"semantic record header ABI");
  require(semantic_bytes_+header.size()+payload<=13486,"semantic total byte cap");write(header.data(),header.size());for(const auto& row:values)write(row.data(),row.size());++semantic_records_;
 }
 void record_row(uint32_t tag,uint32_t ordinal,uint32_t width,const Bytes& value){record(tag,ordinal,width,Rows{value});}
 uint64_t expected_semantic_bytes()const{return 72+24*(uint64_t(2)*k_+4)+uint64_t(L_)*packed(uint64_t(n_)*ell_)+uint64_t(k_)*(packed(uint64_t(2)*n_*w_+n_)+packed(uint64_t(2)*n_))+3*packed(n_);}
 void finish_semantics(bool success){
  if(benchmark_){if(buffer_sealed_){require(!success||buffer_success_,"semantic memory already sealed unsuccessfully");return;}
   if(!semantic_initialized_){require(!success,"semantic memory never opened");return;}
   if(success)require(!semantic_failed_&&semantic_records_==uint64_t(2)*k_+4&&semantic_bytes_==expected_semantic_bytes(),"semantic memory record/byte closure");
   buffer_sealed_=true;buffer_success_=success;return;}

  if(fd_<0){require(!success||(semantic_complete_&&semantic_closed_&&!semantic_failed_),"successful semantic file already closed");return;}
  std::exception_ptr failure;
  try{struct stat st{};require(::fstat(fd_,&st)==0&&st.st_size>=0&&uint64_t(st.st_size)==semantic_bytes_,"semantic actual file size");
   if(success)require(!semantic_failed_&&semantic_records_==uint64_t(2)*k_+4&&semantic_bytes_==expected_semantic_bytes(),"semantic successful record/byte closure");
  }catch(...){failure=std::current_exception();semantic_failed_=true;}
  const int closing=fd_;fd_=-1;const int rc=::close(closing);semantic_closed_=rc==0;if(rc!=0)semantic_failed_=true;
  semantic_complete_=success&&!failure&&semantic_closed_&&!semantic_failed_;
  if(failure)std::rethrow_exception(failure);require(rc==0,"semantic stream close");
 }
 // Called by main only after protocol() has returned or thrown. No transport.
 void persist_semantics(){
  if(!benchmark_||!semantic_initialized_||semantic_closed_)return;
  require(buffer_sealed_&&fd_<0&&buffered_.size()==semantic_bytes_,"semantic memory persistence state");
  fd_=::open(buffered_path_.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);require(fd_>=0,"exclusive deferred semantic create");
  try{size_t done=0;while(done<buffered_.size()){const ssize_t n=::write(fd_,buffered_.data()+done,buffered_.size()-done);
    if(n<0&&errno==EINTR)continue;require(n>0,"deferred semantic write");done+=size_t(n);}
   struct stat st{};require(::fstat(fd_,&st)==0&&st.st_size>=0&&uint64_t(st.st_size)==semantic_bytes_,"deferred semantic actual bytes");
   const int closing=fd_;fd_=-1;require(::close(closing)==0,"deferred semantic close");semantic_closed_=true;
   semantic_complete_=buffer_success_&&!semantic_failed_;Bytes().swap(buffered_);
  }catch(...){semantic_failed_=true;throw;}
 }
 uint64_t semantic_records()const{return semantic_records_;}
 uint64_t semantic_bytes()const{return semantic_bytes_;}
 bool semantic_closed()const{return semantic_closed_;}
 bool semantic_complete()const{return semantic_complete_;}
 bool semantic_failed()const{return semantic_failed_;}
 std::string semantic_sha256()const{return semantic_initialized_?digest(semantic_hash_):"";}
};
} // namespace matched_s_evidence
