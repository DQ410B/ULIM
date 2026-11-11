namespace dense_profile {
struct Profile {uint64_t frontG,backG,front_stages,back_stages,front_takes,back_takes,front_segments,back_segments,batches,front_batches,max_take,front_EF,back_EF,recipient_ALICE;};
static Profile get(uint32_t n){if(n==32)return {622080ULL,20019817ULL,132ULL,143ULL,2372ULL,8157ULL,2380ULL,8462ULL,315ULL,10ULL,17408ULL,155520ULL,5005512ULL,67328ULL};throw std::runtime_error("exact supplementary D profile");}
}
