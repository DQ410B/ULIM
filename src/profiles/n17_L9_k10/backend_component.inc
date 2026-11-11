namespace fused_backend {
using namespace ulim_gmw;
using Bytes=std::vector<unsigned char>;
using Clock=std::chrono::steady_clock;
using TP=Clock::time_point;
static double elapsed(TP t){return std::chrono::duration<double,std::milli>(Clock::now()-t).count();}
static void need(bool x,const char* message){if(!x)throw std::runtime_error(message);}
static uint32_t r32(std::istream& f){unsigned char b[4];f.read((char*)b,4);need(bool(f),"short circuit");return uint32_t(b[0])|(uint32_t(b[1])<<8)|(uint32_t(b[2])<<16)|(uint32_t(b[3])<<24);}
static std::string quote(const std::string& x){std::ostringstream o;o<<'"';for(unsigned char c:x){if(c=='"'||c=='\\')o<<'\\'<<c;else if(c=='\n')o<<"\\n";else if(c=='\r')o<<"\\r";else if(c=='\t')o<<"\\t";else if(c<32)o<<"?";else o<<c;}o<<'"';return o.str();}
static void append32(Bytes& out,uint32_t x){for(unsigned i=0;i<4;++i)out.push_back(static_cast<unsigned char>(x>>(8*i)));}
static void append64(Bytes& out,uint64_t x){for(unsigned i=0;i<8;++i)out.push_back(static_cast<unsigned char>(x>>(8*i)));}
static uint64_t r64(std::istream& f){uint64_t low=r32(f),high=r32(f);return low|(high<<32);}
static Bytes hash_bytes(const void* data,size_t size){Bytes out(32);need(SHA256(static_cast<const unsigned char*>(data),size,out.data())!=nullptr,"SHA256 failure");return out;}
static std::string hex(const Bytes& bytes){std::ostringstream f;f<<std::hex<<std::setfill('0');for(auto x:bytes)f<<std::setw(2)<<unsigned(x);return f.str();}
static Bytes decode_binding(const std::string& text){need(text.size()==64,"application binding length");Bytes out(32);
 auto nibble=[](char c)->unsigned{if(c>='0'&&c<='9')return unsigned(c-'0');if(c>='a'&&c<='f')return unsigned(c-'a'+10);throw std::runtime_error("application binding lowercase hex");};
 for(size_t i=0;i<32;++i)out[i]=static_cast<unsigned char>((nibble(text[2*i])<<4)|nibble(text[2*i+1]));return out;}
static std::string read_file(const std::string& path,size_t cap){std::ifstream f(path,std::ios::binary|std::ios::ate);need(bool(f),"input file open");
 auto length=f.tellg();need(length>=0&&uint64_t(length)<=cap,"input file byte cap");std::string out(size_t(length),'\0');f.seekg(0);if(!out.empty())f.read(&out[0],out.size());
 need(bool(f),"input file read");char extra;need(!f.get(extra)&&f.eof(),"input file exact EOF");return out;}
static void exclusive_bytes(const std::string& path,const Bytes& bytes){int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);need(fd>=0,"exclusive private archive create");
 try{size_t at=0;while(at<bytes.size()){ssize_t count=::write(fd,bytes.data()+at,bytes.size()-at);if(count<0&&errno==EINTR)continue;need(count>0,"private archive write");at+=size_t(count);}}
 catch(...){::close(fd);throw;}need(::close(fd)==0,"private archive close");}
template<class IO> static Bytes exchange(const Bytes& own,int party,IO& io){need(own.size()<=INT_MAX,"public packet too long");Bytes other(own.size());
 if(party==ALICE){io.send_data(own.data(),own.size());io.flush();io.recv_data(other.data(),other.size());}
 else{io.recv_data(other.data(),other.size());io.send_data(own.data(),own.size());io.flush();}return other;}
static Bytes slice(const Bytes& a,size_t start,size_t bits){need(start+bits<=8*a.size(),"slice bounds");Bytes b(packed_bytes(bits),0);for(size_t i=0;i<bits;++i)put_bit(b,i,bit_at(a,start+i));return b;}
static void copy_bits(Bytes& dst,size_t offset,const Bytes& src,size_t start,size_t bits){need(offset+bits<=8*dst.size()&&start+bits<=8*src.size(),"copy bounds");for(size_t i=0;i<bits;++i)put_bit(dst,offset+i,bit_at(src,start+i));}
static Bytes random_bits(size_t bits){Bytes b=ulim_io::random_bytes(packed_bytes(bits));for(size_t i=bits;i<8*b.size();++i)put_bit(b,i,0);return b;}
static uint64_t read_word(const Bytes& b,size_t off,size_t w){need(w<=64&&off+w<=8*b.size(),"word bounds");uint64_t x=0;for(size_t i=0;i<w;++i)x|=uint64_t(bit_at(b,off+i))<<i;return x;}
static void write_word(Bytes& b,size_t off,size_t w,uint64_t x){need(off+w<=8*b.size(),"write word bounds");for(size_t i=0;i<w;++i)put_bit(b,off+i,(x>>i)&1);}
static void write_bytes(const std::string& path,const Bytes& b){exclusive_bytes(path,b);}
using Lane=uint64_t;
using LaneBytes=std::vector<Bytes>;
using Producer=ulim_fresh::FreshTripleProducer<LoopbackIO>;
struct Parameters {
 std::string raw_plan;
 uint32_t n=0,L=0,k=0,w=0,ell=0,a=0,bp=0,P=0,h=0,S=0,B=0;uint64_t discard=0,max_batches=0;
 size_t Pa=0,state_bits=0,meta_bits=0,nw=0,row_bits=0;
 void load(const std::string& path){raw_plan=read_file(path,4096);std::istringstream f(raw_plan);std::string magic,extra;
  f>>magic>>n>>L>>k>>w>>ell>>a>>bp>>P>>h>>S>>B>>discard>>max_batches;
  need(bool(f)&&!(f>>extra)&&magic=="ULIM_STANDARD_OT_MATCHED_D_V1","standard OT D public plan");
  need(n==17&&L==9&&k==10&&max_batches==31&&w==33&&bp==16&&B==8&&discard==0,"exact supplementary D parameters");
  uint32_t expected_ell=0,expected_a=0;
  for(uint32_t x=n;x;x>>=1)++expected_ell;
  for(uint32_t x=2*(n+1)-1;x;x>>=1)++expected_a;
  need(ell==expected_ell&&a==expected_a,"public bit widths");
  need(P==(uint32_t(1)<<a)&&h==a&&S==P*a-P+1&&(uint64_t(1)<<w)>uint64_t(L)*n,"public shape arithmetic");
  Pa=size_t(P)*a;state_bits=size_t(P)*(2*a+2+ell);meta_bits=size_t(n)*(1+ell+4*a);nw=size_t(n)*w;row_bits=size_t(n)*(bp+1);
 }
};
struct Node {uint32_t op,a,b,d;};
struct Circuit {
 std::string name,raw;uint32_t ni=0,no=0,depth=0;size_t G=0,file_bytes=0;
 std::vector<Node> nodes;std::vector<uint32_t> outputs;
 std::vector<std::vector<uint32_t>> ands,locals;
 void load(const std::string& folder,const std::string& label,size_t inputs,size_t outbits){
  name=label;raw=read_file(folder+"/"+name+".bin",1027700ULL);std::istringstream f(raw,std::ios::in|std::ios::binary);
  char magic[8];f.read(magic,8);need(bool(f)&&std::memcmp(magic,"UPGMW001",8)==0,"circuit magic");
  uint32_t nn=r32(f);ni=r32(f);no=r32(f);
  need(nn>=2&&nn<=64134&&inputs>=1&&inputs<=2884&&outbits>=1&&outbits<=1297&&ni==inputs&&no==outbits,"circuit IO/size guard");
  nodes.resize(nn);std::vector<uint8_t> input_seen(ni,0);
  for(uint32_t i=0;i<nn;++i){auto& q=nodes[i];q={r32(f),r32(f),r32(f),r32(f)};need(q.op<=3,"opcode");
   if(q.op==0){need(q.a<ni&&q.b==0&&q.d==0&&!input_seen[q.a],"input ordinal");input_seen[q.a]=1;}
   else if(q.op==1)need(q.a<=1&&q.b==0&&q.d==0,"constant node");
   else{need(q.a<i&&q.b<i,"topology");need(q.d==std::max(nodes[q.a].d,nodes[q.b].d)+(q.op==3),"AND depth");}
   G+=(q.op==3);depth=std::max(depth,q.d);
  }
  for(auto x:input_seen)need(x==1,"missing input ordinal");
  outputs.resize(no);for(auto& o:outputs){o=r32(f);need(o<nn,"output wire");}
  char extra;need(!f.get(extra),"trailing circuit bytes");file_bytes=20+16*size_t(nn)+4*size_t(no);need(file_bytes==raw.size(),"exact circuit encoded length");
  ands.resize(depth+1);locals.resize(depth+1);
  for(uint32_t i=0;i<nn;++i)(nodes[i].op==3?ands[nodes[i].d]:locals[nodes[i].d]).push_back(i);
  for(uint32_t d=1;d<=depth;++d)need(!ands[d].empty(),"empty AND layer");
 }
};
struct Stage {
 std::string name;size_t index=0,round=0,chunk=0,vertex=0,lanes=0;bool evaluated=false;
 uint64_t input_bits=0,output_bits=0,G=0,depth=0,logical_triples=0,pool_begin=0,pool_end=0;
 uint64_t online_bytes=0,recipient_bytes=0,public_bytes=0,pad_rng_bytes=0,shuffle_rng_bytes=0,preprocess_bytes=0;
 double prepare_ms=0,online_ms=0,reveal_ms=0,local_controls_ms=0,triple_take_ms=0,archive_ms=0;
 bool archive_attempted=false,archive_complete=false,evidence_finalized=false;uint64_t archive_payload_bytes=0;
 uint64_t request_begin=0,request_end=0,segment_begin=0,segment_end=0,segment_count=0;
 LaneBytes input,output,ar_state,own_permutation,own_controls,recipient_clear;
 Bytes triple_a,triple_b,triple_c,sent_ef,received_ef,sent_recipient,received_recipient,sent_public,received_public;
 std::vector<ulim_fresh::Segment> segments;
};
struct Record {
 matched_s_evidence::EvidencePolicy* evidence=nullptr;uint64_t observed_segment_count=0;bool final_evidence_finalized=false;
 bool capture()const{need(evidence!=nullptr,"backend evidence policy attached");return evidence->capture_gate_material();}
 uint64_t pool_begin=0,produced_begin=0,delivered_begin=0,discarded_begin=0,preprocess_begin=0,batches_begin=0,request_begin=0,segment_begin=0;
 bool parent_archive_attempted=false,final_archive_attempted=false;
 std::string phase_span_json="null",audit_mode;uint64_t completed_batches_delta=0;
 Parameters p;int party=0;std::string status="failed",error,archive_prefix;
 double stage_archive_ms=0;uint64_t stage_archive_payload_bytes=0,max_stage_payload_bytes=0;
 uint64_t imported_worlds=0,agreement_bytes=0,preprocess_bytes=0,total_bytes=0,totalG=0,produced=0,consumed=0,delivered=0,discarded=0,unused=0;
 double load_ms=0,circuit_load_ms=0,runtime_circuit_load_ms=0,connection_ms=0,total_main_ms=0,protocol_ms=0;
 Bytes parent_input,app_binding,final_seed_bits;std::string app_binding_hex,parent_input_sha256,public_agreement_hex,local_ipv4,peer_ipv4;LaneBytes own_parent,metadata,ar_state;std::vector<Stage> stages;
 std::vector<ulim_fresh::BatchRecord> batches;std::vector<ulim_fresh::Segment> segments;
};
static void decode_parents(Record& r,const Bytes& input){const auto& p=r.p;need(input.size()<=6336,"local parent byte cap");const std::string raw(input.begin(),input.end());r.parent_input=input;
 r.parent_input_sha256=hex(hash_bytes(raw.data(),raw.size()));std::istringstream f(raw,std::ios::in|std::ios::binary);char magic[8];f.read(magic,8);need(bool(f)&&std::memcmp(magic,"ULPAR001",8)==0,"parent file magic");
 const uint32_t party=r32(f),n=r32(f),L=r32(f),ell=r32(f);const uint64_t payload=r64(f);const size_t row_bits=size_t(p.n)*p.ell,row_bytes=packed_bytes(row_bits);
 need(party==uint32_t(r.party)&&n==p.n&&L==p.L&&ell==p.ell&&payload==p.L*row_bytes,"parent file public header");Bytes binding(32);f.read((char*)binding.data(),binding.size());need(bool(f)&&binding==r.app_binding,"parent file application binding");
 r.own_parent.assign(p.L,Bytes(row_bytes,0));for(auto& row:r.own_parent){f.read((char*)row.data(),row.size());need(bool(f),"parent file row");if(row_bits%8)need((row.back()>>(row_bits%8))==0,"parent file row padding");}
 char extra;need(!f.get(extra)&&f.eof()&&raw.size()==64+payload,"parent file exact EOF");r.imported_worlds=p.L;
 // Individual XOR shares need only be ell-bit words; a share need not be <=n.
}
static void archive_stage(Stage& s,Record& r,const std::string& prefix);
static void finish_stage(Stage& s,Record& r,const std::string& prefix);
static LaneBytes evaluate(const Circuit& c,Stage& s,Record& rec,LoopbackIO& io,Producer& prod){
 const int party=rec.party;const uint64_t B=s.input.size();need(B>=1&&B<=rec.p.B,"stage lane bound");const Lane active_mask=(Lane(1)<<B)-1;s.lanes=B;
 s.input_bits=c.ni;s.output_bits=c.no;s.G=c.G;s.depth=c.depth;s.logical_triples=c.G*B;s.pool_begin=prod.global_cursor();s.request_begin=s.request_end=prod.next_request_id();s.segment_begin=s.segment_end=prod.segment_count();
 need(s.input.size()==B,"input lanes");for(const auto& x:s.input)need(x.size()==packed_bytes(c.ni),"stage input size");
 if(rec.capture()){s.triple_a.assign(packed_bytes(s.logical_triples),0);s.triple_b=s.triple_a;s.triple_c=s.triple_a;}
 std::vector<Lane> values(c.nodes.size(),0);uint64_t at=0;
 auto local=[&](size_t d){for(uint32_t i:c.locals[d]){const auto& q=c.nodes[i];
  if(q.op==0){Lane x=0;for(size_t l=0;l<B;++l)x|=Lane(bit_at(s.input[l],q.a))<<l;values[i]=x;}
  else if(q.op==1)values[i]=party==BOB&&q.a?active_mask:0;
  else values[i]=(values[q.a]^values[q.b])&active_mask;
 }};
 TP tm=Clock::now();local(0);s.online_ms+=elapsed(tm);
 for(size_t d=1;d<c.ands.size();++d){const auto& layer=c.ands[d];uint64_t layerbits=uint64_t(layer.size())*B;
  tm=Clock::now();uint64_t pre=io.counter;auto tr=prod.take(layerbits);s.triple_take_ms+=elapsed(tm);s.preprocess_bytes+=io.counter-pre;
  need(tr.bit_count==layerbits,"producer returned bit count");
  if(rec.capture()){copy_bits(s.triple_a,at,tr.a,0,layerbits);copy_bits(s.triple_b,at,tr.b,0,layerbits);copy_bits(s.triple_c,at,tr.c,0,layerbits);}
  if(rec.capture())s.segments.insert(s.segments.end(),tr.segments.begin(),tr.segments.end());s.segment_count+=tr.segments.size();at+=layerbits;s.pool_end=prod.global_cursor();s.request_end=prod.next_request_id();s.segment_end=prod.segment_count();
  tm=Clock::now();Bytes packet(packed_bytes(2*layerbits),0);
  for(size_t j=0;j<layer.size();++j){const auto& q=c.nodes[layer[j]];
   write_word(packet,2*j*B,B,values[q.a]^read_word(tr.a,j*B,B));
   write_word(packet,(2*j+1)*B,B,values[q.b]^read_word(tr.b,j*B,B));
  }
  uint64_t before=io.counter;auto peer=exchange(packet,party,io);
  need(io.counter-before==packet.size(),"layer sent meter");s.online_bytes+=io.counter-before;
  if((2*layerbits)%8)need((peer.back()>>((2*layerbits)%8))==0,"peer packet padding");
  if(rec.capture()){s.sent_ef.insert(s.sent_ef.end(),packet.begin(),packet.end());s.received_ef.insert(s.received_ef.end(),peer.begin(),peer.end());}
  for(size_t j=0;j<layer.size();++j){Lane e=read_word(packet,2*j*B,B)^read_word(peer,2*j*B,B),f=read_word(packet,(2*j+1)*B,B)^read_word(peer,(2*j+1)*B,B);
   Lane aa=read_word(tr.a,j*B,B),bb=read_word(tr.b,j*B,B),cc=read_word(tr.c,j*B,B);
   values[layer[j]]=(cc^(e&bb)^(f&aa)^(party==BOB?(e&f):0))&active_mask;
  }
  local(d);s.online_ms+=elapsed(tm);
 }
 need(at==s.logical_triples&&prod.global_cursor()==s.pool_begin+s.logical_triples,"stage cursor closure");
 LaneBytes result(B,Bytes(packed_bytes(c.no),0));
 for(size_t i=0;i<c.no;++i)for(size_t l=0;l<B;++l)put_bit(result[l],i,(values[c.outputs[i]]>>l)&1);
 if(rec.capture())s.output=result;else LaneBytes().swap(s.input);s.evaluated=true;return result;
}
static LaneBytes recipient(const LaneBytes& share,size_t fieldbits,Record& rec,LoopbackIO& io,Stage& s){
 size_t B=share.size();need(B==s.lanes,"recipient lanes");TP t=Clock::now();uint64_t before=io.counter;
 Bytes packet(packed_bytes(fieldbits*B),0);for(size_t i=0;i<fieldbits;++i)for(size_t l=0;l<B;++l)put_bit(packet,i*B+l,bit_at(share[l],i));
 LaneBytes result;
 if(rec.party==ALICE){if(rec.capture())s.sent_recipient=packet;io.send_data(packet.data(),packet.size());io.flush();}
 else{Bytes other(packet.size());io.recv_data(other.data(),other.size());if(rec.capture())s.received_recipient=other;if((fieldbits*B)%8)need((other.back()>>((fieldbits*B)%8))==0,"recipient high bits");
  result.assign(B,Bytes(packed_bytes(fieldbits),0));for(size_t i=0;i<fieldbits;++i)for(size_t l=0;l<B;++l)put_bit(result[l],i,bit_at(packet,i*B+l)^bit_at(other,i*B+l));}
 s.recipient_bytes+=io.counter-before;s.reveal_ms+=elapsed(t);
 need(io.counter-before==(rec.party==ALICE?packet.size():0),"recipient sent meter");return result;
}
static std::vector<int> controls_for(const std::vector<int>& pi){
 const size_t P=pi.size();need(P&&!(P&(P-1)),"permutation power-of-two");
 std::vector<int> pos(P,-1);for(size_t i=0;i<P;++i){need(pi[i]>=0&&size_t(pi[i])<P&&pos[pi[i]]<0,"permutation validity");pos[pi[i]]=int(i);}
 if(P==1)return {};
 const size_t m=P/2;std::vector<int> color(P,-1),starts={pi[P-2]};
 for(size_t i=0;i<P;++i)starts.push_back(int(i));
 for(int start:starts){if(color[start]>=0)continue;color[start]=0;std::vector<int> stack={start};
  while(!stack.empty()){int v=stack.back();stack.pop_back();
   for(int u:{v^1,pi[pos[v]^1]}){int required=1-color[v];if(color[u]<0){color[u]=required;stack.push_back(u);}else need(color[u]==required,"Waksman bipartite colors");}
  }
 }
 need(color[pi[P-2]]==0&&color[pi[P-1]]==1,"fixed last output pair");
 std::vector<int> out,upper,lower,last;
 for(size_t j=0;j<m;++j)out.push_back(color[2*j]);
 for(size_t j=0;j<m-1;++j)last.push_back(color[pi[2*j]]);
 for(size_t j=0;j<m;++j){int x=pi[2*j],y=pi[2*j+1];if(color[x])std::swap(x,y);need(color[x]==0&&color[y]==1,"subnetwork colors");upper.push_back(x/2);lower.push_back(y/2);}
 auto u=controls_for(upper),l=controls_for(lower);out.insert(out.end(),u.begin(),u.end());out.insert(out.end(),l.begin(),l.end());out.insert(out.end(),last.begin(),last.end());return out;
}
static uint32_t uniform_below(uint32_t bound,uint64_t& used){
 need(bound>0,"uniform bound");if(bound==1)return 0;
 const uint64_t limit=((uint64_t(1)<<32)/bound)*bound;
 for(;;){auto b=ulim_io::random_bytes(4);used+=4;uint32_t x=uint32_t(b[0])|(uint32_t(b[1])<<8)|(uint32_t(b[2])<<16)|(uint32_t(b[3])<<24);if(uint64_t(x)<limit)return x%bound;}
}
static std::vector<int> random_permutation(size_t P,uint64_t& used){
 std::vector<int> p(P);for(size_t i=0;i<P;++i)p[i]=int(i);
 for(size_t i=0;i<P;++i){size_t j=i+uniform_below(uint32_t(P-i),used);std::swap(p[i],p[j]);}return p;
}
static Bytes packed_words(const std::vector<int>& x,size_t w){Bytes out(packed_bytes(x.size()*w),0);for(size_t i=0;i<x.size();++i)write_word(out,i*w,w,uint64_t(x[i]));return out;}
static Bytes control_bits(const std::vector<int>& pi,size_t S){auto c=controls_for(pi);need(c.size()==S,"control count");return packed_words(c,1);}
struct Spec {std::string name;size_t inputs,outputs,calls;};
static uint64_t preprocess_sum(const Producer& p){uint64_t n=0;for(const auto& b:p.batches())n+=b.sent_bytes;return n;}
static uint64_t next_request(const Producer& p){return p.next_request_id();}
static void begin_phase(Record& r,const Producer& p){r.pool_begin=p.global_cursor();r.produced_begin=p.produced();r.delivered_begin=p.delivered();r.discarded_begin=p.discarded();r.preprocess_begin=preprocess_sum(p);r.batches_begin=p.completed_batches();r.request_begin=next_request(p);r.segment_begin=p.segment_count();}
static void snapshot(Record& r,const Producer& p){
 r.produced=p.produced()-r.produced_begin;r.consumed=p.consumed()-r.pool_begin;r.delivered=p.delivered()-r.delivered_begin;r.discarded=p.discarded()-r.discarded_begin;
 r.preprocess_bytes=preprocess_sum(p)-r.preprocess_begin;
 r.completed_batches_delta=p.completed_batches()-r.batches_begin;
}
struct KernelGuard {uint64_t bytes,ni,no,nodes,G,depth;const char* sha;};
static const std::array<KernelGuard,9>& kernel_guards(uint32_t n){
 need(n==17,"exact supplementary kernel n");
 static const std::array<KernelGuard,9> guards={{
  {1027700ULL,85ULL,384ULL,64134ULL,13325ULL,266ULL,"c113d1d935dbf9037baac5a059bf23220736cf85f8cb0f20316613cce7285c8f"},
  {136132ULL,705ULL,384ULL,8411ULL,1926ULL,11ULL,"559a700ecb9ec2845e699b7ed82ecaf77a51d6bfe256df877f5bb065589c25f5"},
  {574036ULL,1410ULL,768ULL,35684ULL,8472ULL,29ULL,"d59d489aecbae48b2c2e55c3b7c06bac332ea719dc8dba3245d3e266494150d2"},
  {32040ULL,384ULL,1297ULL,1677ULL,405ULL,5ULL,"8ecfb206044d5877ffe92209f44c7df9945d2bf3946b957e236091736982a431"},
  {943316ULL,1858ULL,1216ULL,58652ULL,14374ULL,28ULL,"de51fb62e8cebc74a4a579def4f5437e383aabbb82e6850183fa66e473f9220a"},
  {457440ULL,2884ULL,1071ULL,28321ULL,6172ULL,59ULL,"b792510e1edbea4a9a1311bb08c4a48c55a2f54d6d5a5c1b11c6936dbfb08b53"},
  {348088ULL,2210ULL,561ULL,21614ULL,5270ULL,53ULL,"71049447d26a71726aa915d0d9bb721d74c8eaee2c134ba9a7b09486f5670b53"},
  {160620ULL,1139ULL,34ULL,10029ULL,2261ULL,176ULL,"5d94a8e83cbcbcb5aa39e094faa7d36db37595c9db827ee21ed50f021a4c365a"},
  {11736ULL,17ULL,17ULL,728ULL,183ULL,106ULL,"cffa01cfbce86b2a39021b1b3147d8447e5d2ef6927735dd432484402c542510"},
 }};return guards;
}
using Kernels=std::vector<std::unique_ptr<Circuit>>;
static Kernels load_kernels(Record& rec,const std::string& folder){
 const auto& p=rec.p;const int party=rec.party;
 std::array<Spec,9> specs={{{"raw",size_t(p.n)*p.ell,p.Pa,p.L},{"mask",p.Pa+p.S,p.Pa,size_t(p.L)*p.h},
  {"advance",2*p.Pa+2*p.S,2*p.Pa,size_t(p.L)*p.h},{"prep",p.Pa,p.n+p.P+p.state_bits,p.L},
  {"second",p.state_bits+2*p.S,p.state_bits,size_t(p.L)*p.h},
  {"final",p.Pa+p.n+p.P+p.state_bits+2*p.S+p.nw,p.meta_bits+p.nw,p.L},
  {"update",3*p.nw+p.meta_bits+p.n,p.nw,size_t(p.L)*(p.k-1)},
  {"select",2*p.nw+p.n,2*size_t(p.n),p.k},{"fill",p.n,p.n,1}}};
 TP ls=Clock::now();uint64_t bytes=0;std::vector<std::unique_ptr<Circuit>> circuits;const auto& guards=kernel_guards(p.n);
 for(size_t i=0;i<specs.size();++i){const auto& s=specs[i];circuits.emplace_back(new Circuit);auto& c=*circuits.back();c.load(folder,s.name,s.inputs,s.outputs);const auto& g=guards[i];
  bytes+=c.file_bytes;need(bytes<=3691108ULL,"complete scaled backend circuit byte cap");
  need(c.file_bytes==g.bytes&&c.ni==g.ni&&c.no==g.no&&c.nodes.size()==g.nodes&&c.G==g.G&&c.depth==g.depth,"exact saved backend circuit profile");
  need(hex(hash_bytes(c.raw.data(),c.raw.size()))==g.sha,"exact saved backend circuit bytes");rec.totalG+=uint64_t(c.G)*s.calls;}
 need(rec.totalG==dense_profile::get(p.n).backG,"standard OT matched D exact backend logical gate-lane guard");
 need(rec.totalG<=p.max_batches*ulim_fresh::kBatchBits,"bounded backend gate capacity");rec.circuit_load_ms=elapsed(ls);
 return circuits;
}
static void protocol(Record& rec,const Kernels& circuits,LoopbackIO& io,Producer& prod){
 const auto& p=rec.p;const int party=rec.party;
 auto kernel=[&](const std::string& label)->const Circuit&{for(const auto& c:circuits)if(c->name==label)return *c;throw std::runtime_error("backend kernel name");};
 begin_phase(rec,prod);TP begin_time=Clock::now();uint64_t begin=io.counter;
 try{
  const size_t chunks=(p.L+p.B-1)/p.B;
  const size_t expected_stages=chunks*(3*p.h+3)+chunks*(p.k-1)+p.k+1;
  rec.stages.reserve(expected_stages);
  auto stage=[&](const std::string& name,size_t round,size_t chunk=0,size_t vertex=0)->Stage&{if(!rec.stages.empty())finish_stage(rec.stages.back(),rec,rec.archive_prefix);need(rec.stages.size()<71,"backend stage count cap");rec.stages.emplace_back();auto& s=rec.stages.back();s.name=name;s.round=round;s.chunk=chunk;s.vertex=vertex;s.index=rec.stages.size()-1;return s;};
  need(rec.imported_worlds==p.L&&rec.own_parent.size()==p.L,"imported parent world count");
  rec.metadata.resize(p.L);rec.ar_state.resize(p.L);
  auto construct=[&](size_t world_begin){const size_t B=std::min(size_t(p.B),size_t(p.L)-world_begin);
  auto& rs=stage("raw",0,world_begin);rs.input=LaneBytes(rec.own_parent.begin()+world_begin,rec.own_parent.begin()+world_begin+B);LaneBytes J=evaluate(kernel("raw"),rs,rec,io,prod);
  LaneBytes F(B,Bytes(packed_bytes(p.Pa),0));if(party==BOB)for(auto& f:F)for(size_t i=0;i<p.P;++i)write_word(f,i*p.a,p.a,i);
  std::vector<LaneBytes> cached;cached.reserve(p.h);
  for(size_t r=0;r<p.h;++r){
   auto& ms=stage("mask",r,world_begin);const auto& mc=kernel("mask");TP t=Clock::now();ms.input.assign(B,Bytes(packed_bytes(mc.ni),0));LaneBytes keys(B);if(rec.capture())ms.own_permutation.resize(B);
   for(size_t l=0;l<B;++l){copy_bits(ms.input[l],0,J[l],0,p.Pa);
    if(party==ALICE){auto pi=random_permutation(p.P,ms.shuffle_rng_bytes);if(rec.capture())ms.own_permutation[l]=packed_words(pi,p.a);TP ct=Clock::now();keys[l]=control_bits(pi,p.S);ms.local_controls_ms+=elapsed(ct);copy_bits(ms.input[l],p.Pa,keys[l],0,p.S);}}
   ms.prepare_ms=elapsed(t);auto mo=evaluate(mc,ms,rec,io,prod);auto K=recipient(mo,p.Pa,rec,io,ms);
   if(party==BOB){if(rec.capture())ms.recipient_clear=K;for(size_t l=0;l<B;++l){std::vector<int> pi(p.P);for(size_t i=0;i<p.P;++i)pi[i]=int(read_word(K[l],i*p.a,p.a));TP ct=Clock::now();keys[l]=control_bits(pi,p.S);ms.local_controls_ms+=elapsed(ct);}}
   for(const auto& key:keys)need(key.size()==packed_bytes(p.S),"owned cached controls");if(rec.capture())ms.own_controls=keys;cached.push_back(keys);
   auto& as=stage("advance",r,world_begin);const auto& ac=kernel("advance");t=Clock::now();as.input.assign(B,Bytes(packed_bytes(ac.ni),0));
   for(size_t l=0;l<B;++l){copy_bits(as.input[l],0,J[l],0,p.Pa);copy_bits(as.input[l],p.Pa,F[l],0,p.Pa);copy_bits(as.input[l],2*p.Pa+(party==ALICE?0:p.S),keys[l],0,p.S);}
   as.prepare_ms=elapsed(t);auto ao=evaluate(ac,as,rec,io,prod);for(size_t l=0;l<B;++l){J[l]=slice(ao[l],0,p.Pa);F[l]=slice(ao[l],p.Pa,p.Pa);}
  }
  auto& ps=stage("prep",0,world_begin);ps.input=F;auto po=evaluate(kernel("prep"),ps,rec,io,prod);
  LaneBytes cycle(B),anchor(B),state(B);for(size_t l=0;l<B;++l){cycle[l]=slice(po[l],0,p.n);anchor[l]=slice(po[l],p.n,p.P);state[l]=slice(po[l],p.n+p.P,p.state_bits);}
  for(size_t r=0;r<p.h;++r){auto& ss=stage("second",r,world_begin);const auto& sc=kernel("second");TP t=Clock::now();ss.input.assign(B,Bytes(packed_bytes(sc.ni),0));
   for(size_t l=0;l<B;++l){copy_bits(ss.input[l],0,state[l],0,p.state_bits);copy_bits(ss.input[l],p.state_bits+(party==ALICE?0:p.S),cached[r][l],0,p.S);}ss.prepare_ms=elapsed(t);
   state=evaluate(sc,ss,rec,io,prod);
  }
  auto& fs=stage("final",0,world_begin);const auto& fc=kernel("final");TP t=Clock::now();fs.input.assign(B,Bytes(packed_bytes(fc.ni),0));LaneBytes pads(B);
  for(size_t l=0;l<B;++l){size_t at=0;
   copy_bits(fs.input[l],at,F[l],0,p.Pa);at+=p.Pa;copy_bits(fs.input[l],at,cycle[l],0,p.n);at+=p.n;copy_bits(fs.input[l],at,anchor[l],0,p.P);at+=p.P;
   copy_bits(fs.input[l],at,state[l],0,p.state_bits);at+=p.state_bits;copy_bits(fs.input[l],at+(party==ALICE?0:p.S),cached[0][l],0,p.S);at+=2*p.S;
   if(party==ALICE){pads[l]=random_bits(p.nw);fs.pad_rng_bytes+=pads[l].size();copy_bits(fs.input[l],at,pads[l],0,p.nw);}at+=p.nw;need(at==fc.ni,"final field closure");
  }
  fs.prepare_ms=elapsed(t);auto fo=evaluate(fc,fs,rec,io,prod);LaneBytes masked(B);
  for(size_t l=0;l<B;++l){rec.metadata[world_begin+l]=slice(fo[l],0,p.meta_bits);masked[l]=slice(fo[l],p.meta_bits,p.nw);}
  auto z=recipient(masked,p.nw,rec,io,fs);if(party==BOB&&rec.capture())fs.recipient_clear=z;
  const auto& actual_ar=party==ALICE?pads:z;if(rec.capture())fs.ar_state=actual_ar;for(size_t l=0;l<B;++l)rec.ar_state[world_begin+l]=actual_ar[l];
  };
  for(size_t j=0;j<p.L;j+=p.B)construct(j);
  Bytes selected(packed_bytes(p.n),0);const uint64_t ring_mask=(uint64_t(1)<<p.w)-1;
  for(size_t r=0;r<p.k;++r){auto& ss=stage("select",r);const auto& sc=kernel(ss.name);TP t=Clock::now();ss.input.assign(1,Bytes(packed_bytes(sc.ni),0));
   for(size_t v=0;v<p.n;++v){uint64_t sum=0;for(size_t j=0;j<p.L;++j)sum=(sum+read_word(rec.ar_state[j],v*p.w,p.w))&ring_mask;
    write_word(ss.input[0],(party==ALICE?0:p.nw)+v*p.w,p.w,sum);}
   copy_bits(ss.input[0],2*p.nw,selected,0,p.n);ss.prepare_ms=elapsed(t);rec.evidence->record(2,uint32_t(r),sc.ni,ss.input);auto so=evaluate(sc,ss,rec,io,prod);rec.evidence->record(3,uint32_t(r),sc.no,so);
   Bytes winner=slice(so[0],0,p.n);selected=slice(so[0],p.n,p.n);
   if(r+1==p.k)continue;
   for(size_t j=0;j<p.L;j+=p.B){const size_t B=std::min(size_t(p.B),size_t(p.L)-j);auto& us=stage("update",r,j);const auto& uc=kernel(us.name);t=Clock::now();us.input.assign(B,Bytes(packed_bytes(uc.ni),0));LaneBytes pads(B);
    for(size_t l=0;l<B;++l){copy_bits(us.input[l],party==ALICE?0:p.nw,rec.ar_state[j+l],0,p.nw);copy_bits(us.input[l],2*p.nw,rec.metadata[j+l],0,p.meta_bits);copy_bits(us.input[l],2*p.nw+p.meta_bits,winner,0,p.n);
     if(party==ALICE){pads[l]=random_bits(p.nw);us.pad_rng_bytes+=pads[l].size();copy_bits(us.input[l],2*p.nw+p.meta_bits+p.n,pads[l],0,p.nw);}}
    us.prepare_ms=elapsed(t);auto uo=evaluate(uc,us,rec,io,prod);auto z=recipient(uo,p.nw,rec,io,us);if(party==BOB&&rec.capture())us.recipient_clear=z;
    const auto& actual_ar=party==ALICE?pads:z;if(rec.capture())us.ar_state=actual_ar;for(size_t l=0;l<B;++l)rec.ar_state[j+l]=actual_ar[l];
   }
  }
  auto& fs=stage("fill",0);fs.input={selected};rec.evidence->record(4,p.k,p.n,fs.input);auto out=evaluate(kernel("fill"),fs,rec,io,prod);rec.evidence->record(5,p.k,p.n,out);TP t=Clock::now();uint64_t before=io.counter;
  fs.sent_public=out[0];fs.received_public=exchange(fs.sent_public,party,io);fs.public_bytes=io.counter-before;fs.reveal_ms+=elapsed(t);
  need(fs.public_bytes==packed_bytes(p.n),"final public meter");
  if(p.n%8)need((fs.received_public.back()>>(p.n%8))==0,"final public padding");
  rec.final_seed_bits=fs.sent_public;for(size_t i=0;i<rec.final_seed_bits.size();++i)rec.final_seed_bits[i]^=fs.received_public[i];
  size_t count=0;for(size_t v=0;v<p.n;++v)count+=bit_at(rec.final_seed_bits,v);need(count==p.k,"final k seeds");rec.evidence->record_row(6,p.k,p.n,rec.final_seed_bits);
  finish_stage(rec.stages.back(),rec,rec.archive_prefix);
  for(const auto& saved:rec.stages)need(saved.evidence_finalized&&(!rec.capture()||saved.archive_complete),"all stages evidence-finalized");
  snapshot(rec,prod);need(rec.delivered==rec.totalG&&rec.consumed==rec.totalG&&rec.stages.size()==expected_stages,"backend phase schedule/cursor closure");
  need(rec.discarded==0&&rec.produced==rec.completed_batches_delta*ulim_fresh::kBatchBits&&rec.observed_segment_count==prod.segment_count()-rec.segment_begin&&(!rec.capture()||rec.segments.size()==rec.observed_segment_count),"backend phase allocation conservation");
  io.flush();rec.total_bytes=io.counter-begin;rec.protocol_ms=elapsed(begin_time);
  uint64_t sum=0;for(const auto& s:rec.stages)sum+=s.online_bytes+s.recipient_bytes+s.public_bytes+s.preprocess_bytes;
  need(sum==rec.total_bytes,"backend phase byte closure");rec.status="completed";
 }catch(...){snapshot(rec,prod);rec.total_bytes=io.counter-begin;rec.protocol_ms=elapsed(begin_time);throw;}
 // Local stage archives were flushed while live; protocol time includes them.
 // The fused driver retains transport ownership through global finalization.
}
static void write_segment(std::ostream& f,const ulim_fresh::Segment& s){
 f<<"{\"request_id\":"<<s.request_id<<",\"batch_id\":"<<s.batch_id<<",\"offset\":"<<s.offset<<",\"length\":"<<s.length<<",\"global_begin\":"<<s.global_begin<<",\"global_end\":"<<s.global_end<<",\"discarded\":"<<(s.discarded?"true":"false")<<"}";
}
static void write_segments(std::ostream& f,const std::vector<ulim_fresh::Segment>& v){f<<"[";for(size_t i=0;i<v.size();++i){if(i)f<<",";write_segment(f,v[i]);}f<<"]";}
static std::string lane_suffix(size_t l){std::ostringstream s;s<<"_lane"<<std::setw(2)<<std::setfill('0')<<l;return s.str();}
static void write_lanes(const std::string& prefix,const std::string& suffix,const LaneBytes& values){for(size_t l=0;l<values.size();++l)if(!values[l].empty())write_bytes(prefix+lane_suffix(l)+suffix+".bin",values[l]);}
static void archive_stage(Stage& s,Record& r,const std::string& prefix){
 need(r.capture(),"stage archive requires complete gate capture");
 need(!s.archive_attempted,"stage archive exactly once");s.archive_attempted=true;TP began=Clock::now();
 uint64_t payload=0;
 for(const auto* lanes:{&s.input,&s.output,&s.ar_state,&s.own_permutation,&s.own_controls,&s.recipient_clear})for(const auto& x:*lanes)payload+=x.size();
 for(const auto* x:{&s.triple_a,&s.triple_b,&s.triple_c,&s.sent_ef,&s.received_ef,&s.sent_recipient,&s.received_recipient,&s.sent_public,&s.received_public})payload+=x->size();
std::ostringstream st;st<<prefix<<"_stage"<<std::setw(2)<<std::setfill('0')<<s.index<<"_"<<s.name;auto stem=st.str();
  write_lanes(stem,"_input",s.input);if(s.evaluated)write_lanes(stem,"_output",s.output);
  write_lanes(stem,"_own_permutation",s.own_permutation);write_lanes(stem,"_own_controls",s.own_controls);write_lanes(stem,"_recipient_clear",s.recipient_clear);write_lanes(stem,"_ar_state",s.ar_state);
  write_bytes(stem+"_triple_a.bin",s.triple_a);write_bytes(stem+"_triple_b.bin",s.triple_b);write_bytes(stem+"_triple_c.bin",s.triple_c);
  write_bytes(stem+"_sent_ef.bin",s.sent_ef);write_bytes(stem+"_received_ef.bin",s.received_ef);
  write_bytes(stem+"_sent_recipient.bin",s.sent_recipient);write_bytes(stem+"_received_recipient.bin",s.received_recipient);write_bytes(stem+"_sent_public.bin",s.sent_public);write_bytes(stem+"_received_public.bin",s.received_public);
 s.archive_payload_bytes=payload;r.stage_archive_payload_bytes+=payload;r.max_stage_payload_bytes=std::max(r.max_stage_payload_bytes,payload);
 for(auto* lanes:{&s.input,&s.output,&s.ar_state,&s.own_permutation,&s.own_controls,&s.recipient_clear})LaneBytes().swap(*lanes);
 for(auto* x:{&s.triple_a,&s.triple_b,&s.triple_c,&s.sent_ef,&s.received_ef,&s.sent_recipient,&s.received_recipient,&s.sent_public,&s.received_public})Bytes().swap(*x);
 s.archive_complete=true;s.archive_ms=elapsed(began);r.stage_archive_ms+=s.archive_ms;
}
static void finish_stage(Stage& s,Record& r,const std::string& prefix){
 need(!s.evidence_finalized,"stage evidence finalized once");
 if(r.capture())archive_stage(s,r,prefix);
 else{
  need(!s.archive_attempted&&!s.archive_complete&&s.triple_a.empty()&&s.triple_b.empty()&&s.triple_c.empty()&&s.sent_ef.empty()&&s.received_ef.empty()&&s.segments.empty(),"benchmark has no gate archive material");
  for(auto* rows:{&s.input,&s.output,&s.ar_state,&s.own_permutation,&s.own_controls,&s.recipient_clear})LaneBytes().swap(*rows);
  for(auto* bytes:{&s.sent_recipient,&s.received_recipient,&s.sent_public,&s.received_public})Bytes().swap(*bytes);
 }
 s.evidence_finalized=true;
}
static void archive_final(Record& r,const std::string& prefix){
 if(!r.capture()){if(r.final_evidence_finalized)return;for(auto& s:r.stages)if(!s.evidence_finalized)finish_stage(s,r,prefix);r.final_evidence_finalized=true;return;}
 if(r.final_archive_attempted)return;r.final_archive_attempted=true;
 try{if(!r.parent_archive_attempted&&!r.parent_input.empty()){r.parent_archive_attempted=true;write_bytes(prefix+"_parent_input.bin",r.parent_input);}write_bytes(prefix+"_final_seed_bits.bin",r.final_seed_bits);
 write_lanes(prefix,"_own_parent_share",r.own_parent);
 // Preserve an unattempted partial stage on protocol failure; never retry a failed archive write.
 for(auto& s:r.stages)if(!s.archive_attempted)archive_stage(s,r,prefix);
 write_lanes(prefix,"_metadata_share",r.metadata);write_lanes(prefix,"_mass_ar_state",r.ar_state);r.final_evidence_finalized=true;
 }catch(const std::exception& e){r.status="failed";if(!r.error.empty())r.error+="; ";r.error+=std::string("archive: ")+e.what();}
}
static void save_record(Record& r,const std::string& meters){
 struct rusage usage{};getrusage(RUSAGE_SELF,&usage);std::ostringstream f;f.precision(17);
 f<<"{\"schema\":\"standard_ot_d_backend_phase_v1\",\"backend_id\":\"standard_iknp_rom_bitot_v1\",\"phase\":\"backend\",\"app_binding_hex\":"<<quote(r.app_binding_hex)<<",\"public_agreement_hex\":"<<quote(r.public_agreement_hex)
  <<",\"local_ipv4\":"<<quote(r.local_ipv4)<<",\"peer_ipv4\":"<<quote(r.peer_ipv4)<<",\"parent_input_sha256\":"<<quote(r.parent_input_sha256)<<",\"imported_worlds\":"<<r.imported_worlds<<",\"actual_new_worlds\":0,\"parent_input_origin\":\"local_dense_native\""
  <<",\"audit_mode\":"<<quote(r.audit_mode)<<",\"status\":"<<quote(r.status)<<",\"error\":"<<quote(r.error)<<",\"party\":"<<r.party<<",\"n\":"<<r.p.n<<",\"L\":"<<r.p.L<<",\"k\":"<<r.p.k<<",\"bp\":"<<r.p.bp<<",\"w\":"<<r.p.w<<",\"ell\":"<<r.p.ell<<",\"a\":"<<r.p.a<<",\"P\":"<<r.p.P<<",\"h\":"<<r.p.h<<",\"S\":"<<r.p.S<<",\"B\":"<<r.p.B<<",\"discard\":"<<r.p.discard<<",\"max_batches\":"<<r.p.max_batches
  <<",\"logical_AND\":"<<r.totalG<<",\"produced_triples\":"<<r.produced<<",\"consumed_triples\":"<<r.consumed<<",\"delivered_triples\":"<<r.delivered<<",\"discarded_triples\":"<<r.discarded<<",\"completed_batches_delta\":"<<r.completed_batches_delta
  <<",\"agreement_sent_bytes\":"<<r.agreement_bytes<<",\"preprocess_sent_bytes\":"<<r.preprocess_bytes<<",\"total_sent_bytes\":"<<r.total_bytes
  <<",\"load_ms\":"<<r.load_ms<<",\"circuit_load_ms\":"<<r.circuit_load_ms<<",\"runtime_circuit_load_ms\":"<<r.runtime_circuit_load_ms<<",\"connection_ms\":"<<r.connection_ms<<",\"protocol_ms\":"<<r.protocol_ms<<",\"total_main_ms_excluding_final_archive\":"<<r.total_main_ms
  <<",\"peak_rss_bytes_macos\":"<<usage.ru_maxrss<<",\"public_logical_openings\":"<<(r.final_seed_bits.empty()?0:1)<<",\"post_session_synthetic_debug_archive\":false,\"streamed_stage_archives\":"<<(r.capture()?"true":"false")<<",\"protocol_includes_stage_archive\":"<<(r.capture()&&r.status=="completed"?"true":"false")<<",\"stage_archive_ms\":"<<r.stage_archive_ms<<",\"stage_archive_payload_bytes\":"<<r.stage_archive_payload_bytes<<",\"max_stage_payload_bytes\":"<<r.max_stage_payload_bytes<<",\"phase_span\":"<<r.phase_span_json<<",\"producer_segments\":";if(r.capture())write_segments(f,r.segments);else f<<"null";f<<",\"producer_segment_count\":"<<r.observed_segment_count<<",\"retained_segment_count\":"<<r.segments.size()<<",\"stages\":[";
 for(size_t i=0;i<r.stages.size();++i){if(i)f<<",";const auto& s=r.stages[i];
  f<<"{\"index\":"<<s.index<<",\"name\":"<<quote(s.name)<<",\"round\":"<<s.round<<",\"chunk\":"<<s.chunk<<",\"vertex\":"<<s.vertex<<",\"lanes\":"<<s.lanes<<",\"evaluated\":"<<(s.evaluated?"true":"false")<<",\"input_bits\":"<<s.input_bits<<",\"output_bits\":"<<s.output_bits<<",\"and_gates\":"<<s.G<<",\"and_depth\":"<<s.depth<<",\"logical_triples\":"<<s.logical_triples<<",\"pool_begin\":"<<s.pool_begin<<",\"pool_end\":"<<s.pool_end
   <<",\"online_sent_bytes\":"<<s.online_bytes<<",\"recipient_sent_bytes\":"<<s.recipient_bytes<<",\"public_sent_bytes\":"<<s.public_bytes<<",\"preprocess_sent_bytes\":"<<s.preprocess_bytes<<",\"pad_rng_bytes\":"<<s.pad_rng_bytes<<",\"shuffle_rng_bytes\":"<<s.shuffle_rng_bytes<<",\"prepare_ms\":"<<s.prepare_ms<<",\"online_ms\":"<<s.online_ms<<",\"triple_take_ms\":"<<s.triple_take_ms<<",\"reveal_ms\":"<<s.reveal_ms<<",\"local_controls_ms\":"<<s.local_controls_ms<<",\"request_begin\":"<<s.request_begin<<",\"request_end\":"<<s.request_end<<",\"segment_begin\":"<<s.segment_begin<<",\"segment_end\":"<<s.segment_end<<",\"segment_count\":"<<s.segment_count<<",\"evidence_finalized\":"<<(s.evidence_finalized?"true":"false")<<",\"archive_attempted\":"<<(s.archive_attempted?"true":"false")<<",\"archive_complete\":"<<(s.archive_complete?"true":"false")<<",\"archive_ms\":"<<s.archive_ms<<",\"archive_payload_bytes\":"<<s.archive_payload_bytes<<",\"segments\":";if(r.capture())write_segments(f,s.segments);else f<<"null";f<<"}";
 }f<<"]}\n";const std::string encoded=f.str();write_bytes(meters,Bytes(encoded.begin(),encoded.end()));
}
} // namespace fused_backend
