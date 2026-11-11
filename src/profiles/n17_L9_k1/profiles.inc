namespace dense_profile {
struct Profile {uint64_t frontG,backG,front_stages,back_stages,front_takes,back_takes,front_segments,back_segments,batches,front_batches,max_take,front_EF,back_EF,recipient_ALICE;};
static Profile get(uint32_t n){if(n==17)return {55930ULL,1519267ULL,37ULL,44ULL,663ULL,1758ULL,663ULL,1782ULL,25ULL,1ULL,7680ULL,14200ULL,380034ULL,3224ULL};throw std::runtime_error("exact supplementary D profile");}
}
