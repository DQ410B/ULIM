namespace dense_front {
using namespace fused_backend;
struct Record: fused_backend::Record {Bytes own_input,own_coins;bool input_archive_attempted=false;};
static void finish_record(Record& rec){
 if(rec.final_evidence_finalized)return;
 try{for(auto& s:rec.stages)if(!s.evidence_finalized&&(!rec.capture()||!s.archive_attempted))finish_stage(s,rec,rec.archive_prefix);
  if(rec.capture()&&!rec.input_archive_attempted){rec.input_archive_attempted=true;write_bytes(rec.archive_prefix+"_own_input.bin",rec.own_input);write_bytes(rec.archive_prefix+"_own_coins.bin",rec.own_coins);}
  rec.final_evidence_finalized=true;
 }catch(const std::exception& e){rec.status="failed";if(!rec.error.empty())rec.error+="; ";rec.error+=std::string("dense front evidence: ")+e.what();throw;}
}
static const std::array<KernelGuard,2>& front_guards(uint32_t n){
 need(n==32,"exact supplementary kernel n");
 static const std::array<KernelGuard,2> guards={{
  {93636ULL,1088ULL,544ULL,5715ULL,1040ULL,17ULL,"8fe4119e968b98131c9aeb94378431b5e64194622c7f817d3cbae4b7192a3e86"},
  {62956ULL,560ULL,6ULL,3932ULL,575ULL,18ULL,"c1ae928d5c5e1007ce41e2c8bfd02db86397f1cfb6036e8aef1b7f9c8da23d3e"},
 }};return guards;
}
static Kernels load_kernels(Record& rec,const std::string& folder){
 const auto& p=rec.p;const auto expected=dense_profile::get(p.n);const auto& guards=front_guards(p.n);Kernels out;uint64_t bytes=0;TP began=Clock::now();
 const std::array<Spec,2> specs={{{"union_prefix",2*p.row_bits,p.row_bits,p.n},{"sample_single_upper",p.row_bits+p.bp,p.ell,size_t(p.L)*p.n}}};
 for(size_t i=0;i<specs.size();++i){const auto& s=specs[i];out.emplace_back(new Circuit);auto& c=*out.back();c.load(folder,s.name,s.inputs,s.outputs);const auto& q=guards[i];
  need(c.file_bytes==q.bytes&&c.ni==q.ni&&c.no==q.no&&c.nodes.size()==q.nodes&&c.G==q.G&&c.depth==q.depth,"D actual front kernel profile");need(hex(hash_bytes(c.raw.data(),c.raw.size()))==q.sha,"D exact front kernel bytes");bytes+=c.file_bytes;rec.totalG+=c.G*s.calls;
 }
 need(bytes<=156592&&rec.totalG==expected.frontG,"D front aggregate profile");rec.circuit_load_ms=elapsed(began);return out;
}
static void protocol(Record& rec,const Kernels& circuits,LoopbackIO& io,Producer& prod){
 const auto& p=rec.p;const int party=rec.party;const auto expected=dense_profile::get(p.n);
 auto kernel=[&](const std::string& name)->const Circuit&{for(const auto& c:circuits)if(c->name==name)return *c;throw std::runtime_error("D front kernel name");};
 begin_phase(rec,prod);TP began=Clock::now();const uint64_t before=io.counter;
 try{rec.stages.reserve(expected.front_stages);auto stage=[&](const std::string& name,size_t round,size_t chunk=0,size_t vertex=0)->Stage&{if(!rec.stages.empty())finish_stage(rec.stages.back(),rec,rec.archive_prefix);need(rec.stages.size()<expected.front_stages,"D front stage cap");rec.stages.emplace_back();auto& s=rec.stages.back();s.name=name;s.round=round;s.chunk=chunk;s.vertex=vertex;s.index=rec.stages.size()-1;return s;};
  rec.own_parent.assign(p.L,Bytes(packed_bytes(size_t(p.n)*p.ell),0));
  LaneBytes upper(p.n);
  for(size_t v=0;v<p.n;v+=p.B){size_t B=std::min(size_t(p.B),size_t(p.n)-v);auto& s=stage("union_prefix",0,v);const auto& c=kernel(s.name);TP t=Clock::now();
   s.input.assign(B,Bytes(packed_bytes(c.ni),0));for(size_t l=0;l<B;++l)copy_bits(s.input[l],party==ALICE?0:p.row_bits,rec.own_input,(v+l)*p.row_bits,p.row_bits);
   s.prepare_ms=elapsed(t);auto out=evaluate(c,s,rec,io,prod);for(size_t l=0;l<B;++l)upper[v+l]=out[l];
  }
  for(size_t v=0;v<p.n;++v)for(size_t j=0;j<p.L;j+=p.B){size_t B=std::min(size_t(p.B),size_t(p.L)-j);auto& s=stage("sample_single_upper",0,j,v);const auto& c=kernel(s.name);TP t=Clock::now();
   s.input.assign(B,Bytes(packed_bytes(c.ni),0));for(size_t l=0;l<B;++l){copy_bits(s.input[l],0,upper[v],0,p.row_bits);copy_bits(s.input[l],p.row_bits,rec.own_coins,((j+l)*p.n+v)*p.bp,p.bp);}
   s.prepare_ms=elapsed(t);auto out=evaluate(c,s,rec,io,prod);for(size_t l=0;l<B;++l)copy_bits(rec.own_parent[j+l],v*p.ell,out[l],0,p.ell);
  }

  rec.imported_worlds=p.L;upper.clear();upper.shrink_to_fit();finish_stage(rec.stages.back(),rec,rec.archive_prefix);
  for(const auto& s:rec.stages)need(s.evaluated&&s.evidence_finalized&&(!rec.capture()||s.archive_complete),"D front stage completion");
  snapshot(rec,prod);need(rec.stages.size()==expected.front_stages&&rec.consumed==expected.frontG&&rec.delivered==expected.frontG&&rec.discarded==0,"D front G/call conservation");
  need(prod.next_request_id()-rec.request_begin==expected.front_takes&&prod.segment_count()-rec.segment_begin==expected.front_segments&&rec.observed_segment_count==expected.front_segments&&(!rec.capture()||rec.segments.size()==expected.front_segments),"D front allocation schedule");
  io.flush();rec.total_bytes=io.counter-before;rec.protocol_ms=elapsed(began);uint64_t total=0;for(const auto& s:rec.stages)total+=s.preprocess_bytes+s.online_bytes;need(total==rec.total_bytes,"D front phase byte closure");rec.status="completed";
 }catch(...){snapshot(rec,prod);rec.total_bytes=io.counter-before;rec.protocol_ms=elapsed(began);rec.status="failed";throw;}
}
static void save_record(Record& r,const std::string& meters){
 struct rusage usage{};getrusage(RUSAGE_SELF,&usage);std::ostringstream f;f.precision(17);
 f<<"{\"schema\":\"standard_ot_d_frontend_phase_v1\",\"backend_id\":\"standard_iknp_rom_bitot_v1\",\"phase\":\"frontend\",\"app_binding_hex\":"<<quote(r.app_binding_hex)<<",\"public_agreement_hex\":"<<quote(r.public_agreement_hex)
  <<",\"local_ipv4\":"<<quote(r.local_ipv4)<<",\"peer_ipv4\":"<<quote(r.peer_ipv4)<<",\"parent_input_sha256\":"<<quote(r.parent_input_sha256)<<",\"computed_worlds\":"<<r.imported_worlds<<",\"actual_new_worlds\":0,\"parent_input_origin\":\"dense_native_sampling\""
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
} // namespace dense_front
