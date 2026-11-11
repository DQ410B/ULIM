namespace dense_profile {
struct Profile {uint64_t frontG,backG,front_stages,back_stages,front_takes,back_takes,front_segments,back_segments,batches,front_batches,max_take,front_EF,back_EF,recipient_ALICE;};
static Profile get(uint32_t n){if(n==112)return {7633920ULL,62370477ULL,462ULL,155ULL,8302ULL,11098ULL,8417ULL,12049ULL,1069ULL,117ULL,38912ULL,1908480ULL,15593906ULL,213376ULL};throw std::runtime_error("exact supplementary D profile");}
}
