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

# Static zlib is required for fuzz targets (we link it into the fuzzer binary).
if(NOT TARGET zlibstatic)
  message(STATUS "libFuzzer skipped: zlib static library not built (enable ZLIB_BUILD_STATIC)")
  return()
endif()

set(FUZZ_SANITIZERS "fuzzer,address,undefined")

# compress_fuzzer: compress levels, decompress with custom headers
add_executable(compress_fuzzer compress_fuzzer.c)
target_link_libraries(compress_fuzzer PRIVATE zlibstatic)
target_include_directories(compress_fuzzer PRIVATE
  ${zlib_BINARY_DIR}
  ${zlib_SOURCE_DIR})
target_compile_options(compress_fuzzer PRIVATE -fsanitize=${FUZZ_SANITIZERS} -g -O1 ${FUZZ_EXTRA_COMPILE_OPTIONS})
target_link_options(compress_fuzzer PRIVATE -fsanitize=${FUZZ_SANITIZERS} ${FUZZ_EXTRA_LINK_OPTIONS})
set_target_properties(compress_fuzzer PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz)

# uncompress_fuzzer: raw uncompress (decoder stress)
add_executable(uncompress_fuzzer uncompress_fuzzer.c)
target_link_libraries(uncompress_fuzzer PRIVATE zlibstatic)
target_include_directories(uncompress_fuzzer PRIVATE
  ${zlib_BINARY_DIR}
  ${zlib_SOURCE_DIR})
target_compile_options(uncompress_fuzzer PRIVATE -fsanitize=${FUZZ_SANITIZERS} -g -O1 ${FUZZ_EXTRA_COMPILE_OPTIONS})
target_link_options(uncompress_fuzzer PRIVATE -fsanitize=${FUZZ_SANITIZERS} ${FUZZ_EXTRA_LINK_OPTIONS})
set_target_properties(uncompress_fuzzer PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz)

message(STATUS "libFuzzer targets: compress_fuzzer, uncompress_fuzzer (output in build/fuzz/)")
