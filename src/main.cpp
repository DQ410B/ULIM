// One application entry for the main D protocol; no experiment batch runner.
#ifndef ULIM_PROFILE_SOURCE
#error "Configure ULIM_PROFILE with CMake before building"
#endif
#include <iostream>
#include <string>

#define main ulim_protocol_main
#include ULIM_PROFILE_SOURCE
#undef main

int main(int argc, char** argv) {
    if (argc == 1 || (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h"))) {
        std::cout << "ULIM main method D\n"
                  << "Public parameter profile: " << ULIM_PROFILE_NAME << "\n"
                  << "Usage: ulim PARTY PORT BUNDLE_DIR OWNER_FILE COINS_FILE OUTPUT_DIR APP_BINDING_HEX benchmark\n"
                  << "PARTY is 1 or 2; start both parties on the same host.\n"
                  << "Provide external matching circuit bundle and party-local input files.\n"
                  << "OUTPUT_DIR must be a new empty directory with mode 0700.\n"
                  << "ULIM_OT_THREADS sets local OT hash workers; ULIM_OT_HASH_MODE=context selects the parallel backend.\n";
        return argc == 1 ? 2 : 0;
    }
    return ulim_protocol_main(argc, argv);
}
