namespace dense {
using namespace ulim_gmw;using Bytes=std::vector<unsigned char>;using Producer=ulim_fresh::FreshTripleProducer<LoopbackIO>;using Clock=std::chrono::steady_clock;using fused_front::need;using fused_front::quote;
struct Point {
 uint64_t cursor=0,produced=0,consumed=0,delivered=0,discarded=0,unused=0,completed_batches=0,next_request_id=0,segment_index=0,io_sent_bytes=0,preprocess_sent_bytes=0;
};
static Point snapshot(const Producer& prod,const LoopbackIO& io){Point p;p.cursor=prod.global_cursor();p.produced=prod.produced();p.consumed=prod.consumed();p.delivered=prod.delivered();p.discarded=prod.discarded();p.unused=prod.unused();p.completed_batches=prod.completed_batches();p.next_request_id=fused_backend::next_request(prod);p.segment_index=prod.segment_count();p.io_sent_bytes=io.counter;p.preprocess_sent_bytes=fused_backend::preprocess_sum(prod);return p;}
static std::string point_json(const Point& p){std::ostringstream o;o<<"{\"cursor\":"<<p.cursor<<",\"produced\":"<<p.produced<<",\"consumed\":"<<p.consumed<<",\"delivered\":"<<p.delivered<<",\"discarded\":"<<p.discarded<<",\"unused\":"<<p.unused<<",\"completed_batches\":"<<p.completed_batches<<",\"next_request_id\":"<<p.next_request_id<<",\"segment_index\":"<<p.segment_index<<",\"io_sent_bytes\":"<<p.io_sent_bytes<<",\"preprocess_sent_bytes\":"<<p.preprocess_sent_bytes<<"}";return o.str();}
struct Phase {
 std::string name;bool started=false,complete=false;Point begin,end;
 uint64_t logical_AND=0,agreement=0,online=0,recipient=0,public_bytes=0;
 explicit Phase(const char* n):name(n){}
 void start(const Point& p){need(!started,"phase starts once");started=true;begin=end=p;}
 void finish(const Point& p,bool success){end=p;complete=success;}
 uint64_t total()const{return end.io_sent_bytes-begin.io_sent_bytes;}
 uint64_t preprocess()const{return end.preprocess_sent_bytes-begin.preprocess_sent_bytes;}
 uint64_t unclassified()const{const uint64_t known=agreement+online+recipient+public_bytes+preprocess();need(known<=total(),"phase categories exceed IO meter");return total()-known;}
};
static std::string phase_json(const Phase& p){std::ostringstream o;o<<"{\"name\":"<<quote(p.name)<<",\"started\":"<<(p.started?"true":"false")<<",\"complete\":"<<(p.complete?"true":"false")<<",\"begin\":"<<point_json(p.begin)<<",\"end\":"<<point_json(p.end)
 <<",\"logical_AND\":"<<p.logical_AND<<",\"produced_delta\":"<<p.end.produced-p.begin.produced<<",\"consumed_delta\":"<<p.end.consumed-p.begin.consumed<<",\"delivered_delta\":"<<p.end.delivered-p.begin.delivered<<",\"discarded_delta\":"<<p.end.discarded-p.begin.discarded<<",\"completed_batches_delta\":"<<p.end.completed_batches-p.begin.completed_batches
 <<",\"agreement_sent_bytes\":"<<p.agreement<<",\"online_sent_bytes\":"<<p.online<<",\"recipient_sent_bytes\":"<<p.recipient<<",\"public_sent_bytes\":"<<p.public_bytes<<",\"preprocess_sent_bytes\":"<<p.preprocess()<<",\"unclassified_sent_bytes\":"<<p.unclassified()<<",\"total_sent_bytes\":"<<p.total()<<"}";return o.str();}
// One complete physical ledger stream in both modes; no retained queue.
class SegmentWriter {
 int fd_=-1;uint64_t bytes_=0,records_=0;bool initialized_=false,closed_=false,failed_=false;
 SHA256_CTX file_hash_{},records_hash_{};
 void write(const uint8_t* data,size_t count,bool records){
  try{while(count){ssize_t n=::write(fd_,data,count);if(n<0&&errno==EINTR)continue;need(n>0,"segment observer write failure");
    const size_t used=size_t(n);bytes_+=used;need(SHA256_Update(&file_hash_,data,used)==1,"segment file hash update");
    if(records)need(SHA256_Update(&records_hash_,data,used)==1,"segment record hash update");data+=used;count-=used;
  }}catch(...){failed_=true;throw;}
 }
 static std::string finish_hash(const SHA256_CTX& source){auto copy=source;Bytes out(32);need(SHA256_Final(out.data(),&copy)==1,"segment SHA256 final");return fused_backend::hex(out);}
public:
 SegmentWriter()=default;SegmentWriter(const SegmentWriter&)=delete;SegmentWriter& operator=(const SegmentWriter&)=delete;
 ~SegmentWriter(){if(fd_>=0)::close(fd_);}
 void open(const std::string& path){need(fd_<0&&!initialized_,"segment stream opens once");
  need(SHA256_Init(&file_hash_)==1&&SHA256_Init(&records_hash_)==1,"segment hash init");initialized_=true;
  fd_=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);need(fd_>=0,"exclusive segment stream create");
  write(reinterpret_cast<const uint8_t*>("ULSEG001"),8,false);
 }
 void append(const ulim_fresh::Segment& s){need(fd_>=0&&!failed_,"segment stream writable");
  const auto raw=ulim_scaled_ledger::encode(s);write(raw.data(),raw.size(),true);++records_;
 }
 void sync(){need(fd_>=0&&!failed_,"segment stream sync state");try{fused_front::sync_exact(fd_);}catch(...){failed_=true;throw;}}
 void finish(){if(fd_<0)return;std::exception_ptr failure;
  try{struct stat st{};need(::fstat(fd_,&st)==0&&st.st_size>=0&&uint64_t(st.st_size)==bytes_,"actual segment file length");sync();}catch(...){failure=std::current_exception();failed_=true;}
  const int closing=fd_;fd_=-1;const int rc=::close(closing);closed_=rc==0;if(rc!=0)failed_=true;
  if(failure)std::rethrow_exception(failure);need(rc==0,"segment file close failure");
 }
 uint64_t bytes()const{return bytes_;}uint64_t records()const{return records_;}
 bool closed()const{return closed_;}bool failed()const{return failed_;}
 std::string records_sha256()const{return initialized_?finish_hash(records_hash_):"";}
 std::string file_sha256()const{return initialized_?finish_hash(file_hash_):"";}
};
static void batches_json(std::ostream& f,const std::vector<ulim_fresh::BatchRecord>& batches){f<<"[";
 for(size_t i=0;i<batches.size();++i){if(i)f<<",";const auto& b=batches[i];f<<"{\"batch_id\":"<<b.batch_id<<",\"global_begin\":"<<b.global_begin<<",\"global_end\":"<<b.global_end<<",\"bit_count\":"<<b.bit_count<<",\"complete\":"<<(b.complete?"true":"false")<<",\"status\":"<<quote(b.status)<<",\"sent_bytes\":"<<b.sent_bytes<<",\"wall_ms\":"<<b.wall_ms<<",\"cpu_ms\":"<<b.cpu_ms<<",\"phases\":[";
  for(size_t j=0;j<b.phases.size();++j){if(j)f<<",";const auto& x=b.phases[j];f<<"{\"batch_id\":"<<x.batch_id<<",\"direction\":"<<x.direction<<",\"name\":"<<quote(x.name)<<",\"complete\":"<<(x.complete?"true":"false")<<",\"sent_begin\":"<<x.sent_begin<<",\"received_begin\":"<<x.received_begin<<",\"sent_bytes\":"<<x.sent_bytes<<",\"received_bytes\":"<<x.received_bytes<<",\"wall_ms\":"<<x.wall_ms<<",\"cpu_ms\":"<<x.cpu_ms<<"}";}f<<"]}";
 }f<<"]";
}
} // namespace dense
