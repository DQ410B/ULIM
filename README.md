# ULIM main program

Source-only distribution of the **D method** for private influence maximization in sampled linear-threshold graphs. Two native C++ processes execute the two-party protocol using the standard-OT backend and local parallel OT hashing.


## Build

The supported platform is Linux x86_64, including an x86_64 Linux distribution under WSL2. Requirements are CMake 3.16+, a C++17 compiler, OpenSSL 3 development files and POSIX threads. The CPU needs AES-NI, PCLMULQDQ and SSE4.1. Required EMP source dependencies and their license files are included. Python and MP-SPDZ are not required to build or directly start this program.

On Ubuntu, the system packages are `build-essential cmake libssl-dev`.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 4
./build/ulim --help
```

The default public parameter profile is `n112_L64_k10`. To choose another compiled profile, configure a separate build directory, for example:

```sh
cmake -S . -B build-n17 -DCMAKE_BUILD_TYPE=Release -DULIM_PROFILE=n17_L9_k10
cmake --build build-n17 --parallel 4
```

Available profiles are listed in `cmake/profiles.cmake`. The names encode the number of vertices `n`, training worlds `L` and selected seeds `k`. Profiles contain public circuit/resource dimensions, not graph edges or saved experiment outputs. Different dimensions require matching circuit bundles and resource profiles; arbitrary values are not selected with runtime flags. `--parallel 4` controls compilation, not protocol worker threads.

## Run with your own separately prepared inputs

The command format for each party is:

```text
./build/ulim PARTY PORT BUNDLE_DIR OWNER_FILE COINS_FILE OUTPUT_DIR APP_BINDING_HEX benchmark
```

- `PARTY`: 1 or 2. Start one process for each party on the same host, using the same port, public bundle and application binding.
- `PORT`: a free TCP port in 1024–65535. The retained channel connects exclusively through 127.0.0.1.
- `BUNDLE_DIR`: an external matching D circuit bundle, including `plan.txt` and its 11 native kernel files.
- `OWNER_FILE`: this party's packed owner weight table, in destination-major order, with 17-bit unsigned entries. Weights represent probabilities with denominator 65536; the owner union uses entrywise maximum.
- `COINS_FILE`: this party's contribution tape, containing `L*n` little-endian uint16 words. The two contributions are combined by XOR.
- `OUTPUT_DIR`: a new empty directory, created separately for each party with permissions 0700. Native result records and local protocol records are written there.
- `APP_BINDING_HEX`: the matching application binding, a 32-byte value encoded by 64 hexadecimal characters, identical for both parties.
- `benchmark`: the retained native execution mode. It executes the full protocol; it is not a plaintext simulation.

Set `ULIM_OT_THREADS=8` and `ULIM_OT_HASH_MODE=context` in both processes' environments to use the retained parallel hash backend. OT and triple randomness is generated afresh by the native implementation. Fixed training contributions and protocol randomness serve different purposes.

This source-only package has no graph datasets, owner inputs, contribution tapes, compiled circuits, circuit generator, baseline implementations, experiment batches, timing tables or test records. It can be compiled independently. Actual protocol execution requires the external files above. Compiling and displaying help do not start a protocol session. This is the existing fixed-profile native implementation; it is not an arbitrary-new-graph preparation interface or a two-host deployment interface.

## Source layout

| Directory or file | Function |
| --- | --- |
| `src/main.cpp` | Unified application entry and help |
| `src/profiles/<profile>/worker.cpp` | Selects the corresponding D implementation components |
| `frontend_component.inc` | Private sampling and representation construction |
| `backend_component.inc` | Private residual-state optimization and greedy selection |
| `driver_source.inc` | Full protocol orchestration and native result output |
| `shared_driver.inc` | Allocation snapshots, phase counters and shared driver helpers |
| `profiles.inc` | Exact public circuit and preprocessing budgets |
| `support.inc`, `evidence_policy.h` | Circuit/record support used by the native program |
| `src/backend/` | Standard bit-OT, triple production and parallel hash implementations |
| `src/core/` | GMW types, packed values, transport and allocation utilities |
| `third_party/` | Required EMP dependency sources and licenses |
| `cmake/profiles.cmake` | Supported public parameter profiles |

The profile directories retain the implementation's existing specialization boundaries. Only include paths and the application wrapper were reorganized. The algorithm and cryptographic backend have not been redesigned. Results from earlier experimental packages are not included or regenerated here.

Original project authors have not selected a project-wide license for this distribution. Retained third-party licenses apply to their corresponding files; see `THIRD_PARTY_NOTICES.md` and `LICENSE_PROJECT.txt`.
