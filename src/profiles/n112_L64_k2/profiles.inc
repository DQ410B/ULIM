namespace dense_profile {
struct Profile {uint64_t frontG,backG,front_stages,back_stages,front_takes,back_takes,front_segments,back_segments,batches,front_batches,max_take,front_EF,back_EF,recipient_ALICE;};
static Profile get(uint32_t n){if(n==112)return {14855680ULL,104619349ULL,910ULL,227ULL,16366ULL,13218ULL,16589ULL,14814ULL,1824ULL,227ULL,38912ULL,3713920ULL,26155522ULL,190208ULL};throw std::runtime_error("exact supplementary D profile");}
}
