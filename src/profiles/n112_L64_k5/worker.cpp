// Main D protocol translation unit for this public parameter profile.
#include "src/core/gmw_membership.h"
#include "src/backend/small/standard_triple_producer.h"
#include "src/core/loopback_io.h"
#include "src/backend/small/im_pool_trace.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <memory>
#include <openssl/sha.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/resource.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <utility>
#include <exception>
// Namespace alias preserves the frozen evaluator source text while selecting
// the standard IKNP based triple producer.
namespace ulim_fresh = ulim_standard_fresh;
#include "src/profiles/n112_L64_k5/evidence_policy.h"
#include "src/profiles/n112_L64_k5/support.inc"
#include "src/profiles/n112_L64_k5/profiles.inc"
#include "src/profiles/n112_L64_k5/backend_component.inc"
#include "src/profiles/n112_L64_k5/frontend_component.inc"
#include "src/profiles/n112_L64_k5/shared_driver.inc"
#include "src/profiles/n112_L64_k5/driver_source.inc"
