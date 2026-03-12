# libFuzzer fuzz targets for zlib.
# Enable with: cmake -DZLIB_BUILD_FUZZ=ON ..
# Build with Clang and run e.g.: ./compress_fuzzer [corpus_dir] [other options]

if(NOT ZLIB_BUILD_FUZZ)
  return()
endif()

# libFuzzer is supported with Clang (LLVM; Apple Clang often lacks the fuzzer runtime).
if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(STATUS "libFuzzer skipped: need Clang (current: ${CMAKE_C_COMPILER_ID})")
  return()
endif()

# Check that the fuzzer runtime is available (e.g. LLVM Clang has it; Xcode Clang may not).
# On macOS with Homebrew LLVM we need lib/c++ for libc++ (fuzzer runtime is C++).
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
if(APPLE)
  execute_process(COMMAND brew --prefix llvm
    OUTPUT_VARIABLE BREW_LLVM_PREFIX OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET RESULT_VARIABLE BREW_LLVM_RESULT)
  if(BREW_LLVM_RESULT EQUAL 0 AND BREW_LLVM_PREFIX)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -L${BREW_LLVM_PREFIX}/lib/c++ -Wl,-rpath,${BREW_LLVM_PREFIX}/lib/c++")
  endif()
endif()
check_c_source_compiles("int main(void) { return 0; }" HAVE_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)
if(NOT HAVE_LIBFUZZER)
  message(STATUS "libFuzzer skipped: fuzzer runtime not found (on macOS try: brew install llvm, then CC=$(brew --prefix llvm)/bin/clang)")
  return()
endif()

# On macOS with Homebrew LLVM, link against its libc++ (avoids __hash_memory undefined symbol).
set(FUZZ_EXTRA_LINK_OPTIONS "")
set(FUZZ_EXTRA_COMPILE_OPTIONS "")
if(APPLE)
  if(BREW_LLVM_RESULT EQUAL 0 AND BREW_LLVM_PREFIX)
    list(APPEND FUZZ_EXTRA_LINK_OPTIONS -L${BREW_LLVM_PREFIX}/lib/c++ -Wl,-rpath,${BREW_LLVM_PREFIX}/lib/c++)
  endif()
  # Prefer macOS SDK so the compiler finds headers/libs (avoid missing sysroot warning).
  execute_process(COMMAND xcrun --sdk macosx --show-sdk-path
    OUTPUT_VARIABLE MACOS_SDK_PATH OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(MACOS_SDK_PATH)
    list(APPEND FUZZ_EXTRA_COMPILE_OPTIONS -isysroot ${MACOS_SDK_PATH})
  endif()
endif()

# Build a separate instrumented static zlib for fuzzing. This avoids tainting
# the main zlibstatic with sanitizer flags (which would break non-fuzz targets).
# We reuse the same source list but compile with coverage + sanitizer instrumentation.
get_target_property(ZLIB_SRC_FILES zlibstatic SOURCES)
if(NOT ZLIB_SRC_FILES)
  message(STATUS "libFuzzer skipped: could not get zlib source list")
  return()
endif()

# Source paths are relative to zlib source dir; make them absolute.
set(ZLIB_SRC_FILES_ABS "")
foreach(src ${ZLIB_SRC_FILES})
  if(IS_ABSOLUTE ${src})
    list(APPEND ZLIB_SRC_FILES_ABS ${src})
  else()
    list(APPEND ZLIB_SRC_FILES_ABS ${zlib_SOURCE_DIR}/${src})
  endif()
endforeach()

add_library(zlibstatic_fuzz STATIC ${ZLIB_SRC_FILES_ABS})
target_include_directories(zlibstatic_fuzz PUBLIC
  ${zlib_BINARY_DIR}
  ${zlib_SOURCE_DIR})
target_compile_definitions(zlibstatic_fuzz PRIVATE ZLIB_BUILD)
# CRITICAL: -fsanitize=fuzzer-no-link adds SanCov instrumentation so the fuzzer
# can see which code paths are hit inside zlib (not just the harness).
target_compile_options(zlibstatic_fuzz PRIVATE
  -fsanitize=fuzzer-no-link,address,undefined -g -O1 -fno-omit-frame-pointer ${FUZZ_EXTRA_COMPILE_OPTIONS})

set(FUZZ_SANITIZERS "fuzzer,address,undefined")

# Helper: add a fuzz target with standard options.
function(add_fuzz_target name source)
  add_executable(${name} ${source})
  target_link_libraries(${name} PRIVATE zlibstatic_fuzz)
  target_include_directories(${name} PRIVATE
    ${zlib_BINARY_DIR}
    ${zlib_SOURCE_DIR})
  target_compile_options(${name} PRIVATE -fsanitize=${FUZZ_SANITIZERS} -g -O1 ${FUZZ_EXTRA_COMPILE_OPTIONS})
  target_link_options(${name} PRIVATE -fsanitize=${FUZZ_SANITIZERS} ${FUZZ_EXTRA_LINK_OPTIONS})
  set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz)
endfunction()

# --- Fuzz targets ---
# compress_fuzzer:          compress at different levels, decompress with custom headers
add_fuzz_target(compress_fuzzer            compress_fuzzer.c)
# uncompress_fuzzer:        raw uncompress() decoder stress
add_fuzz_target(uncompress_fuzzer          uncompress_fuzzer.c)
# inflate_fuzzer:           streaming inflate with fuzz-driven window bits and flush modes
add_fuzz_target(inflate_fuzzer             inflate_fuzzer.c)
# deflate_roundtrip_fuzzer: deflate + inflate round-trip with varied parameters
add_fuzz_target(deflate_roundtrip_fuzzer   deflate_roundtrip_fuzzer.c)

set(FUZZ_TARGETS compress_fuzzer uncompress_fuzzer inflate_fuzzer deflate_roundtrip_fuzzer)
message(STATUS "libFuzzer targets: ${FUZZ_TARGETS} (output in build/fuzz/)")
