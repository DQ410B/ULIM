namespace dense_profile {
struct Profile {uint64_t frontG,backG,front_stages,back_stages,front_takes,back_takes,front_segments,back_segments,batches,front_batches,max_take,front_EF,back_EF,recipient_ALICE;};
static Profile get(uint32_t n){if(n==112)return {14855680ULL,112106330ULL,910ULL,254ULL,16366ULL,15324ULL,16589ULL,17034ULL,1938ULL,227ULL,38912ULL,3713920ULL,28027465ULL,278912ULL};throw std::runtime_error("exact supplementary D profile");}
}
