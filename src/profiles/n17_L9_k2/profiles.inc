namespace dense_profile {
struct Profile {uint64_t frontG,backG,front_stages,back_stages,front_takes,back_takes,front_segments,back_segments,batches,front_batches,max_take,front_EF,back_EF,recipient_ALICE;};
static Profile get(uint32_t n){if(n==17)return {55930ULL,1568941ULL,37ULL,47ULL,663ULL,2040ULL,663ULL,2064ULL,25ULL,1ULL,7680ULL,14200ULL,392558ULL,3856ULL};throw std::runtime_error("exact supplementary D profile");}
}
