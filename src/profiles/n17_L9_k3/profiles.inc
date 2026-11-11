namespace dense_profile {
struct Profile {uint64_t frontG,backG,front_stages,back_stages,front_takes,back_takes,front_segments,back_segments,batches,front_batches,max_take,front_EF,back_EF,recipient_ALICE;};
static Profile get(uint32_t n){if(n==17)return {55930ULL,1618649ULL,37ULL,50ULL,663ULL,2322ULL,663ULL,2347ULL,26ULL,1ULL,7680ULL,14200ULL,405084ULL,4488ULL};throw std::runtime_error("exact supplementary D profile");}
}
