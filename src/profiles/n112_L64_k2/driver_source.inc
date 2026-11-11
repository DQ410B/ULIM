// D-specific complete native orchestration. Shared helpers precede this file.
namespace dense {
struct Result {
 double protocol_wall_ms=0;bool protocol_timing_complete=false;
 std::vector<std::pair<std::string,Bytes>> deferred_public_packets;
 matched_s_evidence::EvidencePolicy evidence;SegmentWriter segment_writer;
 std::string status="FAIL",error,state="PREPARED",audit_mode,bundle_dir,archive_dir,owner_file,coins_file,app_binding_hex,public_agreement_hex,local_ipv4,peer_ipv4;
 Bytes app_binding;int party=0,port=0;uint32_t mode_code=0;dense_profile::Profile expected{};
 dense_front::Record front;fused_backend::Record back;Point last;
 std::unique_ptr<ulim_standard_im_evidence::Archive> ot_archive;
 std::array<Phase,5> phases={{Phase("setup"),Phase("frontend"),Phase("transition"),Phase("backend"),Phase("finalization")}};
 std::vector<ulim_fresh::BatchRecord> batches;std::vector<ulim_fresh::Segment> segments;
 std::string owner_input_sha256,coins_input_sha256;uint64_t owner_input_bytes=0,coins_input_bytes=0,retained_segment_count=0;
 bool paths_ready=false,producer_poisoned=false;uint64_t actual_sent=0,actual_received=0;double elapsed_ms=0;
};
static void mkdir_private(const std::string& path){need(::mkdir(path.c_str(),0700)==0,"exclusive private subdirectory create");}
static void save_bytes(const std::string& path,const Bytes& bytes){fused_backend::exclusive_bytes(path,bytes);}
static void save_text(const std::string& path,const std::string& value){save_bytes(path,Bytes(value.begin(),value.end()));}
static void append_error(Result& r,const std::string& value){r.status="FAIL";r.state="FAILED";if(!r.error.empty())r.error+="; ";r.error+=value;}
static Bytes read_packed(const std::string& path,size_t bits){const size_t bytes=ulim_gmw::packed_bytes(bits);const auto raw=fused_backend::read_file(path,bytes);need(raw.size()==bytes,"private input exact byte length");Bytes value(raw.begin(),raw.end());if(bits%8)need((value.back()>>(bits%8))==0,"private input zero tail");return value;}
static void load(Result& r,int argc,char** argv){
 need(argc==9,"PARTY PORT BUNDLE_DIR OWNER_FILE COINS_FILE ARCHIVE_DIR APP_BINDING_HEX AUDIT_MODE");
 const uint64_t party=fused_front::decimal(argv[1]),port=fused_front::decimal(argv[2]);need((party==1||party==2)&&port>=1024&&port<=65535,"party and loopback port");
 r.audit_mode=argv[8];need(r.audit_mode=="benchmark","supplementary benchmark only");r.mode_code=r.audit_mode=="full"?0:(r.audit_mode=="stream"?1:2);
 r.party=int(party);r.port=int(port);r.bundle_dir=argv[3];r.owner_file=argv[4];r.coins_file=argv[5];r.archive_dir=argv[6];r.app_binding_hex=argv[7];r.app_binding=fused_front::hex_decode(r.app_binding_hex);need(r.app_binding.size()==32,"public digest binding must be exactly 32 bytes");
 struct stat st{};need(::lstat(r.archive_dir.c_str(),&st)==0&&S_ISDIR(st.st_mode)&&(st.st_mode&0777)==0700,"existing private archive directory");
 r.back.evidence=&r.evidence;r.back.p.load(r.bundle_dir+"/plan.txt");r.expected=dense_profile::get(r.back.p.n);const auto& p=r.back.p;
 need(p.max_batches==r.expected.batches&&r.expected.frontG+r.expected.backG<=r.expected.batches*ulim_fresh::kBatchBits,"D exact total budget");
 r.back.party=r.party;r.back.audit_mode=r.audit_mode;r.back.app_binding=r.app_binding;r.back.app_binding_hex=r.app_binding_hex;r.back.archive_prefix=r.archive_dir+"/backend/party"+std::to_string(r.party);
 r.front.p=p;r.front.evidence=&r.evidence;r.front.party=r.party;r.front.audit_mode=r.audit_mode;r.front.app_binding=r.app_binding;r.front.app_binding_hex=r.app_binding_hex;r.front.archive_prefix=r.archive_dir+"/frontend/party"+std::to_string(r.party);
 need(p.n==17||r.audit_mode=="benchmark","n112 supports benchmark only; qualification is n17 full/stream");
 r.evidence.configure(r.audit_mode,r.party,p.n,p.L,p.k,p.ell,p.w);
 r.front.own_input=read_packed(r.owner_file,size_t(p.n)*p.n*(p.bp+1));r.front.own_coins=read_packed(r.coins_file,size_t(p.L)*p.n*p.bp);
 for(size_t i=0;i<size_t(p.n)*p.n;++i)need(fused_backend::read_word(r.front.own_input,i*(p.bp+1),p.bp+1)<=(uint64_t(1)<<p.bp),"private owner weight domain");
 r.owner_input_bytes=r.front.own_input.size();r.coins_input_bytes=r.front.own_coins.size();r.owner_input_sha256=fused_backend::hex(fused_backend::hash_bytes(r.front.own_input.data(),r.front.own_input.size()));r.coins_input_sha256=fused_backend::hex(fused_backend::hash_bytes(r.front.own_coins.data(),r.front.own_coins.size()));
}
static Bytes digest(const Result& r,const fused_backend::Kernels& front,const fused_backend::Kernels& back){
 SHA256_CTX context;need(SHA256_Init(&context)==1,"D public digest init");
 auto put=[&](const void* data,size_t bytes){need(SHA256_Update(&context,data,bytes)==1,"D public digest update");};
 auto u32=[&](uint32_t x){Bytes b;fused_front::append32(b,x);put(b.data(),b.size());};auto u64=[&](uint64_t x){Bytes b;fused_front::append64(b,x);put(b.data(),b.size());};
 const std::string domain="ULIM_LT_STANDARD_OT_MATCHED_D_V1";put(domain.data(),domain.size());put(r.app_binding.data(),r.app_binding.size());u32(r.mode_code);
 u64(ulim_fresh::kBatchBits);u64(r.expected.batches);u64(r.expected.max_take);
 u64(r.back.p.raw_plan.size());put(r.back.p.raw_plan.data(),r.back.p.raw_plan.size());for(uint64_t x:{r.expected.front_stages,r.expected.frontG,r.expected.back_stages,r.expected.backG,r.expected.front_takes+r.expected.back_takes,r.expected.front_segments+r.expected.back_segments})u64(x);
 u32(11);auto add=[&](const fused_backend::Kernels& kernels){for(const auto& c:kernels){u32(uint32_t(c->name.size()));put(c->name.data(),c->name.size());u64(c->raw.size());put(c->raw.data(),c->raw.size());}};add(front);add(back);
 Bytes result(32);need(SHA256_Final(result.data(),&context)==1,"D public digest final");return result;
}
static Bytes public_exchange(const Bytes& own,Phase& phase,int party,LoopbackIO& io){uint64_t before=io.counter;
 try{auto peer=fused_front::exchange(own,party,io);phase.agreement+=io.counter-before;return peer;}catch(...){phase.agreement+=io.counter-before;throw;}
}
static void agreed_packet(const Bytes& own,Result& r,Phase& phase,LoopbackIO& io,const char* stem){auto peer=public_exchange(own,phase,r.party,io);if(r.evidence.benchmark()){need(r.deferred_public_packets.size()<6,"bounded deferred public packets");r.deferred_public_packets.emplace_back(std::string("sent_")+stem+".bin",own);r.deferred_public_packets.emplace_back(std::string("received_")+stem+".bin",peer);}else{save_bytes(r.archive_dir+"/transition/sent_"+stem+".bin",own);save_bytes(r.archive_dir+"/transition/received_"+stem+".bin",peer);}need(peer==own,"D public packet agreement");}
static uint64_t evaluated_G(const fused_backend::Record& r){uint64_t x=0;for(const auto& s:r.stages)if(s.evaluated)x+=s.logical_triples;return x;}
static uint64_t evaluated_stages(const fused_backend::Record& r){uint64_t x=0;for(const auto& s:r.stages)x+=s.evaluated;return x;}
static void categories(Phase& p,const fused_backend::Record& r){p.logical_AND=evaluated_G(r);p.online=p.recipient=p.public_bytes=0;for(const auto& s:r.stages){p.online+=s.online_bytes;p.recipient+=s.recipient_bytes;p.public_bytes+=s.public_bytes;}}
static void snapshot_global(Result& r,const Producer& prod,const LoopbackIO& io){r.last=snapshot(prod,io);r.batches=prod.batches();r.producer_poisoned=prod.poisoned();r.retained_segment_count=prod.retained_segment_count();if(r.audit_mode=="full"&&!prod.poisoned())r.segments=prod.segments();}
static Bytes parent_frame(const Result& r){const auto& p=r.back.p;Bytes raw={'U','L','P','A','R','0','0','1'};
 for(uint32_t x:{uint32_t(r.party),p.n,p.L,p.ell})fused_front::append32(raw,x);fused_front::append64(raw,uint64_t(p.L)*ulim_gmw::packed_bytes(size_t(p.n)*p.ell));raw.insert(raw.end(),r.app_binding.begin(),r.app_binding.end());for(const auto& row:r.front.own_parent)raw.insert(raw.end(),row.begin(),row.end());
 need(raw.size()==64+size_t(p.L)*ulim_gmw::packed_bytes(size_t(p.n)*p.ell),"computed parent frame exact size");return raw;
}
static void protocol(Result& r){
 auto front=dense_front::load_kernels(r.front,r.bundle_dir);auto back=fused_backend::load_kernels(r.back,r.bundle_dir);need(r.front.totalG==r.expected.frontG&&r.back.totalG==r.expected.backG,"D exact full AND profile");
 const Bytes public_digest=digest(r,front,back);r.public_agreement_hex=fused_backend::hex(public_digest);r.front.public_agreement_hex=r.back.public_agreement_hex=r.public_agreement_hex;
 need(public_digest.size()==32,"public agreement digest must be exactly 32 bytes");std::array<uint8_t,32> agreed_binding{};std::copy(public_digest.begin(),public_digest.end(),agreed_binding.begin());
 LoopbackIO io(r.party==ALICE,r.port);r.local_ipv4=io.local_ipv4();r.peer_ipv4=io.peer_ipv4();r.front.local_ipv4=r.back.local_ipv4=r.local_ipv4;r.front.peer_ipv4=r.back.peer_ipv4=r.peer_ipv4;
 if(r.evidence.capture_gate_material()){
  r.ot_archive=std::make_unique<ulim_standard_im_evidence::Archive>(r.archive_dir,r.party,agreed_binding,r.expected.frontG+r.expected.backG,r.expected.batches,r.expected.front_takes+r.expected.back_takes,r.expected.front_segments+r.expected.back_segments);
  io.set_wire_observer([&](bool sent,const unsigned char* data,size_t bytes){r.ot_archive->on_wire(sent,data,bytes);});
 }
 auto observer=[&](const ulim_fresh::Segment& segment){r.evidence.on_segment(segment);
  if(r.state=="FRONTEND"){need(r.front.observed_segment_count<r.expected.front_segments,"D frontend segment cap");++r.front.observed_segment_count;if(r.evidence.capture_gate_material())r.front.segments.push_back(segment);}
  else if(r.state=="BACKEND"){need(r.back.observed_segment_count<r.expected.back_segments,"D backend segment cap");++r.back.observed_segment_count;if(r.evidence.capture_gate_material())r.back.segments.push_back(segment);}
  else throw std::runtime_error("D allocation outside computation phase");
  if(r.evidence.capture_gate_material())r.segment_writer.append(segment);
 };
 typename ulim_standard_ot::StandardOtBitAdapter<LoopbackIO>::Observer ot_observer;
 ulim_standard_fresh::PoolObserver pool_observer;
 if(r.evidence.capture_gate_material()){
  ot_observer=[&](const ulim_standard_ot::TransferObservation& observation){r.ot_archive->on_ot(observation);};
  pool_observer=[&](const ulim_standard_fresh::PoolObservation& observation){r.ot_archive->on_pool(observation);};
 }
 Producer prod(r.party,io,agreed_binding,{r.expected.batches,r.expected.max_take},r.evidence.producer_mode(),r.audit_mode=="full"?r.expected.front_segments+r.expected.back_segments:0,observer,ot_observer,pool_observer);size_t current=0;r.phases[0].start(snapshot(prod,io));
 const auto protocol_begin=Clock::now();
 try{
  agreed_packet(public_digest,r,r.phases[0],io,"initial");r.phases[0].finish(snapshot(prod,io),true);
  current=1;r.state="FRONTEND";r.phases[1].start(snapshot(prod,io));dense_front::protocol(r.front,front,io,prod);dense_front::finish_record(r.front);need(r.front.status=="completed","D frontend completed");
  categories(r.phases[1],r.front);if(r.evidence.capture_gate_material())r.segment_writer.sync();r.phases[1].finish(snapshot(prod,io),true);
  need(r.phases[1].unclassified()==0&&r.phases[1].online==r.expected.front_EF&&r.phases[1].recipient==0&&r.phases[1].public_bytes==0,"D frontend byte profile");
  Point boundary=snapshot(prod,io);need(boundary.cursor==r.expected.frontG&&boundary.consumed==r.expected.frontG&&boundary.delivered==r.expected.frontG&&boundary.discarded==0&&boundary.produced==r.expected.front_batches*ulim_fresh::kBatchBits&&boundary.unused==boundary.produced-boundary.consumed&&boundary.completed_batches==r.expected.front_batches,"D frontend producer conservation");
  need(boundary.next_request_id==r.expected.front_takes&&boundary.segment_index==r.expected.front_segments,"D frontend global allocation boundaries");
  current=2;r.state="TRANSITION";r.phases[2].start(boundary);const Bytes payload=parent_frame(r);fused_backend::decode_parents(r.back,payload);r.evidence.record(1,0,r.back.p.n*r.back.p.ell,r.back.own_parent);
  if(r.evidence.capture_gate_material()){r.back.parent_archive_attempted=true;save_bytes(r.back.archive_prefix+"_parent_input.bin",payload);}
  Bytes ready;for(uint64_t x:{r.expected.front_stages,r.expected.frontG,boundary.produced,boundary.consumed,boundary.delivered,boundary.discarded,boundary.unused,boundary.completed_batches})fused_front::append64(ready,x);need(ready.size()==64,"D ready frame");agreed_packet(ready,r,r.phases[2],io,"ready");io.flush();r.phases[2].finish(snapshot(prod,io),true);need(r.phases[2].total()==64,"D transition exact public bytes");
  current=3;r.state="BACKEND";r.phases[3].start(snapshot(prod,io));fused_backend::protocol(r.back,back,io,prod);fused_backend::archive_final(r.back,r.back.archive_prefix);need(r.back.status=="completed"&&r.back.final_evidence_finalized,"D backend completed with local evidence");
  categories(r.phases[3],r.back);r.phases[3].finish(snapshot(prod,io),true);need(r.phases[3].unclassified()==0&&r.phases[3].preprocess()==r.back.preprocess_bytes&&r.phases[3].online==r.expected.back_EF&&r.phases[3].recipient==(r.party==ALICE?r.expected.recipient_ALICE:0)&&r.phases[3].public_bytes==ulim_gmw::packed_bytes(r.back.p.n),"D backend byte profile");
  current=4;r.state="FINALIZING";r.phases[4].start(snapshot(prod,io));const Point final=snapshot(prod,io);const uint64_t G=r.expected.frontG+r.expected.backG;
  need(evaluated_stages(r.front)==r.expected.front_stages&&evaluated_stages(r.back)==r.expected.back_stages&&evaluated_G(r.front)==r.expected.frontG&&evaluated_G(r.back)==r.expected.backG,"D complete stage/G accounting");
  need(final.cursor==G&&final.consumed==G&&final.delivered==G&&final.discarded==0&&final.produced==r.expected.batches*ulim_fresh::kBatchBits&&final.completed_batches==r.expected.batches&&final.unused==final.produced-G,"D complete producer conservation");
  need(final.next_request_id==r.expected.front_takes+r.expected.back_takes&&final.segment_index==r.expected.front_segments+r.expected.back_segments&&r.evidence.ledger_records_observed()==final.segment_index,"D allocation observation closure");
  if(r.evidence.capture_gate_material())need(r.segment_writer.records()==final.segment_index&&r.segment_writer.bytes()==8+56*final.segment_index,"D physical allocation closure");
  else need(r.segment_writer.records()==0&&r.segment_writer.bytes()==0&&r.front.segments.empty()&&r.back.segments.empty()&&prod.retained_segment_count()==0,"D benchmark no physical/retained ledger");
  r.evidence.finish_semantics(true);Bytes closure;for(uint64_t x:{r.expected.front_stages+r.expected.back_stages,G,final.produced,final.consumed,final.delivered,final.discarded,final.unused,final.completed_batches})fused_front::append64(closure,x);need(closure.size()==64,"D final frame");agreed_packet(closure,r,r.phases[4],io,"final");io.flush();r.protocol_wall_ms=std::chrono::duration<double,std::milli>(Clock::now()-protocol_begin).count();r.protocol_timing_complete=true;r.phases[4].finish(snapshot(prod,io),true);snapshot_global(r,prod,io);
  uint64_t total=0,agreement=0;for(const auto& p:r.phases){need(p.started&&p.complete&&p.unclassified()==0,"D complete adjacent phases");total+=p.total();agreement+=p.agreement;}need(total==io.counter&&agreement==160,"D complete application agreement meter");io.flush();r.actual_sent=io.actual_sent;r.actual_received=io.received;need(r.actual_sent==io.counter,"actual wire send equals application counter after flush");snapshot_global(r,prod,io);if(r.ot_archive){r.ot_archive->finish(r.last.produced,r.last.consumed,r.last.delivered,r.last.discarded,r.last.unused,r.last.completed_batches,r.last.next_request_id,r.last.segment_index,r.actual_sent,r.actual_received);need(r.ot_archive->finished(),"OT pool archive did not finish");}r.status="PASS";r.state="COMPLETE";
 }catch(...){categories(r.phases[1],r.front);categories(r.phases[3],r.back);if(r.phases[current].started)r.phases[current].finish(snapshot(prod,io),false);r.actual_sent=io.actual_sent;r.actual_received=io.received;snapshot_global(r,prod,io);throw;}
}
static std::string global_json(const Result& r){const auto& p=r.back.p;std::ostringstream o;o.precision(17);uint64_t agree=0,online=0,recipient=0,pub=0,pre=0,unknown=0;for(const auto& phase:r.phases){agree+=phase.agreement;online+=phase.online;recipient+=phase.recipient;pub+=phase.public_bytes;pre+=phase.preprocess();unknown+=phase.unclassified();}
 o<<"{\"schema\":\"lt_im_standard_ot_matched_d_worker_v1\",\"backend_id\":\"standard_iknp_rom_bitot_v1\",\"qualification_only\":"<<(r.evidence.benchmark()?"false":"true")<<",\"ot_pool_path\":"<<(r.ot_archive?"\"ot_pool.bin\"":"null")<<",\"sent_wire_path\":"<<(r.ot_archive?"\"sent.bin\"":"null")<<",\"received_wire_path\":"<<(r.ot_archive?"\"received.bin\"":"null")<<",\"ot_archive_finished\":"<<(r.ot_archive&&r.ot_archive->finished()?"true":"false")<<",\"method_id\":\"D\",\"status\":"<<quote(r.status)<<",\"error\":"<<(r.error.empty()?"null":quote(r.error))<<",\"state\":"<<quote(r.state)<<",\"audit_mode\":"<<quote(r.audit_mode)<<",\"party\":"<<r.party<<",\"n\":"<<p.n<<",\"L\":"<<p.L<<",\"k\":"<<p.k<<",\"w\":"<<p.w<<",\"ell\":"<<p.ell<<",\"a\":"<<p.a<<",\"bp\":"<<p.bp<<",\"P\":"<<p.P<<",\"h\":"<<p.h<<",\"S\":"<<p.S<<",\"B\":"<<p.B<<",\"max_batches\":"<<p.max_batches
 <<",\"app_binding_hex\":"<<quote(r.app_binding_hex)<<",\"public_agreement_hex\":"<<quote(r.public_agreement_hex)<<",\"local_ipv4\":"<<quote(r.local_ipv4)<<",\"peer_ipv4\":"<<quote(r.peer_ipv4)<<",\"owner_input_sha256\":"<<quote(r.owner_input_sha256)<<",\"coins_input_sha256\":"<<quote(r.coins_input_sha256)<<",\"owner_input_bytes\":"<<r.owner_input_bytes<<",\"coins_input_bytes\":"<<r.coins_input_bytes<<",\"parent_input_sha256\":"<<quote(r.back.parent_input_sha256)<<",\"final_seed_bitmap_hex\":"<<quote(fused_backend::hex(r.back.final_seed_bits))
 <<",\"frontend_stages\":"<<evaluated_stages(r.front)<<",\"backend_stages\":"<<evaluated_stages(r.back)<<",\"total_circuit_invocations\":"<<evaluated_stages(r.front)+evaluated_stages(r.back)<<",\"logical_AND\":"<<evaluated_G(r.front)+evaluated_G(r.back)
 <<",\"produced\":"<<r.last.produced<<",\"consumed\":"<<r.last.consumed<<",\"delivered\":"<<r.last.delivered<<",\"discarded\":"<<r.last.discarded<<",\"unused\":"<<r.last.unused<<",\"completed_batches\":"<<r.last.completed_batches<<",\"producer_requests\":"<<r.last.next_request_id<<",\"producer_segment_count\":"<<r.last.segment_index<<",\"producer_history_retained\":"<<(r.audit_mode=="full"?"true":"false")<<",\"retained_segment_count\":"<<r.retained_segment_count<<",\"producer_poisoned\":"<<(r.producer_poisoned?"true":"false")
 <<",\"frontend_segment_records_observed\":"<<r.front.observed_segment_count<<",\"backend_segment_records_observed\":"<<r.back.observed_segment_count<<",\"frontend_retained_segment_count\":"<<r.front.segments.size()<<",\"backend_retained_segment_count\":"<<r.back.segments.size()<<",\"ledger_records_observed\":"<<r.evidence.ledger_records_observed()<<",\"ledger_records_sha256\":"<<quote(r.evidence.ledger_records_sha256())
 <<",\"segments_path\":"<<(r.evidence.benchmark()?"null":"\"segments.bin\"")<<",\"segment_stream_bytes\":"<<r.segment_writer.bytes()<<",\"segment_records_written\":"<<r.segment_writer.records()<<",\"segment_records_sha256\":"<<(r.evidence.benchmark()?"null":quote(r.segment_writer.records_sha256()))<<",\"segments_sha256\":"<<(r.evidence.benchmark()?"null":quote(r.segment_writer.file_sha256()))<<",\"segment_file_closed\":"<<(r.segment_writer.closed()?"true":"false")<<",\"segment_file_complete\":"<<(!r.evidence.benchmark()&&r.status=="PASS"&&r.segment_writer.closed()&&!r.segment_writer.failed()&&r.segment_writer.records()==r.last.segment_index&&r.segment_writer.bytes()==8+56*r.last.segment_index?"true":"false")
 <<",\"semantic_path\":\"semantics.bin\",\"semantic_records\":"<<r.evidence.semantic_records()<<",\"semantic_bytes\":"<<r.evidence.semantic_bytes()<<",\"semantic_sha256\":"<<quote(r.evidence.semantic_sha256())<<",\"semantic_file_closed\":"<<(r.evidence.semantic_closed()?"true":"false")<<",\"semantic_file_complete\":"<<(r.evidence.semantic_complete()?"true":"false")<<",\"semantic_failed\":"<<(r.evidence.semantic_failed()?"true":"false")<<",\"per_gate_archive_available\":"<<(r.evidence.capture_gate_material()?"true":"false")<<",\"full_gate_replay_performed\":false"
 <<",\"agreement_sent_bytes\":"<<agree<<",\"online_sent_bytes\":"<<online<<",\"recipient_sent_bytes\":"<<recipient<<",\"public_sent_bytes\":"<<pub<<",\"preprocess_sent_bytes\":"<<pre<<",\"unclassified_sent_bytes\":"<<unknown<<",\"total_sent_bytes\":"<<r.actual_sent<<",\"actual_sent_bytes\":"<<r.actual_sent<<",\"received_bytes\":"<<r.actual_received<<",\"actual_received_bytes\":"<<r.actual_received<<",\"computed_dense_worlds\":"<<(r.phases[1].complete?p.L:0)<<",\"backend_imported_within_session_worlds\":"<<r.back.imported_worlds<<",\"actual_new_LT_worlds\":0,\"reused_training_worlds\":"<<(r.phases[1].complete?p.L:0)<<",\"completed_full_IM_runs\":"<<(r.status=="PASS"?1:0)<<",\"protocol_wall_ms\":"<<r.protocol_wall_ms<<",\"protocol_timing_complete\":"<<(r.protocol_timing_complete?"true":"false")<<",\"benchmark_semantics_deferred\":"<<(r.evidence.benchmark()?"true":"false")<<",\"protocol_timing_boundary\":\"before_initial_digest_exchange_through_final_closure_exchange_flush\",\"elapsed_ms_descriptive_only\":"<<r.elapsed_ms<<",\"phase_spans\":[";
 for(size_t i=0;i<r.phases.size();++i){if(i)o<<",";o<<phase_json(r.phases[i]);}o<<"],\"batches\":";batches_json(o,r.batches);o<<",\"producer_segments\":";if(r.audit_mode=="full"&&!r.producer_poisoned)fused_backend::write_segments(o,r.segments);else o<<"null";o<<"}\n";return o.str();
}
} // namespace dense
int main(int argc,char** argv){
 std::signal(SIGPIPE,SIG_IGN);const auto began=dense::Clock::now();dense::Result r;fused_front::Descriptor result_fd;int code=1;
 try{dense::load(r,argc,argv);result_fd.exclusive(r.archive_dir+"/result.json");dense::mkdir_private(r.archive_dir+"/frontend");dense::mkdir_private(r.archive_dir+"/backend");dense::mkdir_private(r.archive_dir+"/transition");r.paths_ready=true;
  r.evidence.open_semantics(r.archive_dir+"/semantics.bin",r.app_binding);if(r.evidence.capture_gate_material())r.segment_writer.open(r.archive_dir+"/segments.bin");dense::protocol(r);code=0;
 }catch(const std::exception& e){dense::append_error(r,e.what());}catch(...){dense::append_error(r,"nonstandard exception");}
 try{r.evidence.finish_semantics(false);}catch(const std::exception& e){dense::append_error(r,std::string("semantic finalization: ")+e.what());}
 try{r.evidence.persist_semantics();for(const auto& packet:r.deferred_public_packets)dense::save_bytes(r.archive_dir+"/transition/"+packet.first,packet.second);r.deferred_public_packets.clear();}
 catch(const std::exception& e){dense::append_error(r,std::string("deferred evidence: ")+e.what());code=1;}
 try{r.segment_writer.finish();}catch(const std::exception& e){dense::append_error(r,std::string("segment finalization: ")+e.what());}
 if(r.paths_ready){
  try{if(r.phases[1].started)dense_front::finish_record(r.front);}catch(const std::exception& e){dense::append_error(r,std::string("frontend evidence cleanup: ")+e.what());}
  try{if(r.phases[3].started&&!r.back.final_evidence_finalized){if(r.back.error.empty())r.back.error=r.error;fused_backend::archive_final(r.back,r.back.archive_prefix);}}catch(const std::exception& e){dense::append_error(r,std::string("backend evidence cleanup: ")+e.what());}
  r.elapsed_ms=std::chrono::duration<double,std::milli>(dense::Clock::now()-began).count();r.front.total_main_ms=r.back.total_main_ms=r.elapsed_ms;r.front.phase_span_json=dense::phase_json(r.phases[1]);r.back.phase_span_json=dense::phase_json(r.phases[3]);
  try{dense_front::save_record(r.front,r.archive_dir+"/frontend/result.json");}catch(const std::exception& e){dense::append_error(r,std::string("frontend result: ")+e.what());}
  try{fused_backend::save_record(r.back,r.archive_dir+"/backend/result.json");}catch(const std::exception& e){dense::append_error(r,std::string("backend result: ")+e.what());}
 }
 r.elapsed_ms=std::chrono::duration<double,std::milli>(dense::Clock::now()-began).count();
 try{if(result_fd.value>=0){const auto encoded=dense::global_json(r);fused_front::write_exact(result_fd.value,encoded.data(),encoded.size());if(!r.evidence.benchmark())fused_front::sync_exact(result_fd.value);const int closing=result_fd.value;result_fd.value=-1;dense::need(::close(closing)==0,"global result close");}}
 catch(const std::exception& e){std::fprintf(stderr,"D global result failure: %s\n",e.what());return 2;}
 if(r.status!="PASS"){std::fprintf(stderr,"D worker failed: %s\n",r.error.c_str());return 1;}return code;
}
