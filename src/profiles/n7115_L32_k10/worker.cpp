// Main D protocol translation unit for this public parameter profile.
#include "src/core/gmw_membership.h"
#include "src/backend/wide/standard_triple_producer.h"
#include "src/core/loopback_io.h"
#include "src/backend/wide/im_pool_trace.h"
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
#include "src/profiles/n7115_L32_k10/evidence_policy.h"
#include "src/profiles/n7115_L32_k10/support.inc"
#include "src/profiles/n7115_L32_k10/profiles.inc"
#include "src/profiles/n7115_L32_k10/backend_component.inc"
#include "src/profiles/n7115_L32_k10/frontend_component.inc"
#include "src/profiles/n7115_L32_k10/shared_driver.inc"
#include "src/profiles/n7115_L32_k10/driver_source.inc"
