namespace dense_profile {
struct Profile {uint64_t frontG,backG,front_stages,back_stages,front_takes,back_takes,front_segments,back_segments,batches,front_batches,max_take,front_EF,back_EF,recipient_ALICE;};
static Profile get(uint32_t n){if(n==64)return {2491392ULL,56705534ULL,264ULL,155ULL,4744ULL,10360ULL,4782ULL,11225ULL,904ULL,39ULL,38912ULL,622848ULL,14177112ULL,150016ULL};throw std::runtime_error("exact supplementary D profile");}
}
