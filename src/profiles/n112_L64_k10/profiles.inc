namespace dense_profile {
struct Profile {uint64_t frontG,backG,front_stages,back_stages,front_takes,back_takes,front_segments,back_segments,batches,front_batches,max_take,front_EF,back_EF,recipient_ALICE;};
static Profile get(uint32_t n){if(n==112)return {14855680ULL,124584333ULL,910ULL,299ULL,16366ULL,18834ULL,16589ULL,20734ULL,2128ULL,227ULL,38912ULL,3713920ULL,31147370ULL,426752ULL};throw std::runtime_error("exact supplementary D profile");}
}
