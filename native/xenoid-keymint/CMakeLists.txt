cmake_minimum_required(VERSION 3.22)
project(xenoid_keymint LANGUAGES C CXX)

# The xenoid Android 13 KeyMint HAL service. Sources in src/ derive from
# TEESimulator (https://github.com/JingMatrix/TEESimulator); the in-process
# reference KeyMint TA is built from the pinned AOSP checkout under .deps with
# the patches in rust/patches applied.

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Weak-link NDK symbols newer than the minimum SDK so the code builds against a
# low min-SDK; the symbols we use are present on the devices we target.
add_compile_definitions(__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__)

# External inputs, fetched pinned by scripts/fetch-keymint-deps.sh. libbinder_ndk
# and liblog come from the NDK sysroot; BoringSSL resolves at runtime against the
# device's libcrypto, so only its headers (for the Rust bindings) are needed.
set(DEPS_DIR "${CMAKE_SOURCE_DIR}/.deps" CACHE PATH "Pinned dependency checkouts (scripts/fetch-keymint-deps.sh)")
set(BORINGSSL_DIR "${DEPS_DIR}/boringssl" CACHE PATH "BoringSSL source directory containing include/")
if(ANDROID_PLATFORM MATCHES "android-([0-9]+)")
  set(ANDROID_API_LEVEL "${CMAKE_MATCH_1}")
else()
  set(ANDROID_API_LEVEL "29")
endif()

# --- KeyMint AIDL, generated with the NDK backend ---------------------------
# Prefer the newest installed build-tools' aidl (the alphabetically sorted glob
# would otherwise let a leftover 34.0.0 silently win over 36.0.0). AIDL_BIN is a
# plain variable, recomputed on every configure; -DAIDL_BIN=... still wins.
if(NOT AIDL_BIN AND DEFINED ENV{ANDROID_HOME})
  file(GLOB _bt $ENV{ANDROID_HOME}/build-tools/*)
  list(SORT _bt COMPARE NATURAL ORDER DESCENDING)
  foreach(_d ${_bt})
    if(EXISTS ${_d}/aidl)
      set(AIDL_BIN ${_d}/aidl)
      break()
    endif()
  endforeach()
endif()
if(NOT AIDL_BIN)
  find_program(_aidl_on_path aidl)
  set(AIDL_BIN ${_aidl_on_path})
endif()
if(NOT AIDL_BIN)
  message(FATAL_ERROR "aidl not found; set -DAIDL_BIN=/path/to/aidl")
endif()

set(SEC ${DEPS_DIR}/interfaces/security)
set(KM_AIDL ${SEC}/keymint/aidl)
set(SC_AIDL ${SEC}/secureclock/aidl)
set(SS_AIDL ${SEC}/sharedsecret/aidl)
set(AIDL_GEN ${CMAKE_BINARY_DIR}/aidl-gen)

if(NOT EXISTS ${AIDL_GEN}/.done)
  file(MAKE_DIRECTORY ${AIDL_GEN}/src ${AIDL_GEN}/include)
  foreach(pkg keymint secureclock sharedsecret)
    file(GLOB _aidls ${SEC}/${pkg}/aidl/android/hardware/security/${pkg}/*.aidl)
    execute_process(
      COMMAND ${AIDL_BIN} --lang=ndk --structured --stability=vintf --min_sdk_version=29
              -I ${KM_AIDL} -I ${SC_AIDL} -I ${SS_AIDL}
              -o ${AIDL_GEN}/src -h ${AIDL_GEN}/include ${_aidls}
      RESULT_VARIABLE _rc)
    if(NOT _rc EQUAL 0)
      message(FATAL_ERROR "aidl generation failed for ${pkg}")
    endif()
  endforeach()
  if(NOT EXISTS ${AIDL_GEN}/src/android/hardware/security/keymint/IKeyMintDevice.cpp)
    message(FATAL_ERROR "keymint: aidl did not generate IKeyMintDevice.cpp")
  endif()
  file(TOUCH ${AIDL_GEN}/.done)
endif()

set(FN ${DEPS_DIR}/frameworks-native/libs/binder/ndk)
file(GLOB_RECURSE AIDL_SRCS ${AIDL_GEN}/src/*.cpp)
add_library(keymint_aidl STATIC ${AIDL_SRCS})
target_include_directories(keymint_aidl PUBLIC
    ${AIDL_GEN}/include ${FN}/include_cpp ${FN}/include_ndk ${FN}/include_platform)
# Compile the AIDL static lib at API 31 so the generated fromBinder keeps its
# local-binder fallback (gated #if __ANDROID_API__ >= 31); the symbols it then
# references stay undefined here and resolve at runtime against the device's
# libbinder_ndk (the service links with -Wl,-z,undefs).
if(CMAKE_CXX_COMPILER_TARGET MATCHES "[0-9]+$")
  string(REGEX REPLACE "[0-9]+$" "31" _km_target "${CMAKE_CXX_COMPILER_TARGET}")
  target_compile_options(keymint_aidl PRIVATE "--target=${_km_target}")
else()
  message(FATAL_ERROR "keymint: cannot derive an API-31 target from '${CMAKE_CXX_COMPILER_TARGET}'")
endif()

# --- The in-process TA (Rust static library) --------------------------------
if(ANDROID_ABI STREQUAL "arm64-v8a")
  set(RUST_TRIPLE aarch64-linux-android)
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
  set(RUST_TRIPLE armv7-linux-androideabi)
elseif(ANDROID_ABI STREQUAL "x86_64")
  set(RUST_TRIPLE x86_64-linux-android)
elseif(ANDROID_ABI STREQUAL "x86")
  set(RUST_TRIPLE i686-linux-android)
endif()

set(RUST_A ${CMAKE_SOURCE_DIR}/rust/target/${RUST_TRIPLE}/release/libteesim_km.a)
# ALWAYS invoke build.sh and let cargo decide incrementally what to rebuild. An
# OUTPUT custom command with no source DEPENDS only runs when the .a is missing,
# so a Rust source change would otherwise never refresh it. cargo leaves the
# .a's mtime untouched when nothing changed, so this does not needlessly relink.
add_custom_target(rust_ta
    BYPRODUCTS ${RUST_A}
    COMMAND ${CMAKE_COMMAND} -E env
            ABI=${ANDROID_ABI} API=${ANDROID_API_LEVEL} NDK_HOME=${ANDROID_NDK}
            BORINGSSL=${BORINGSSL_DIR}
            bash ${CMAKE_SOURCE_DIR}/rust/build.sh
    VERBATIM USES_TERMINAL)

# --- How the TA reaches BoringSSL --------------------------------------------
# The service links a stub libcrypto.so — empty functions carrying the right
# SONAME — and lets the device's real libcrypto provide the symbols at runtime.
set(CRYPTO_STUB_C ${CMAKE_BINARY_DIR}/libcrypto_stub.c)
file(STRINGS ${CMAKE_SOURCE_DIR}/src/libcrypto.syms _crypto_syms)
set(_stub_body "")
foreach(_s ${_crypto_syms})
  string(APPEND _stub_body "void ${_s}(void){}\n")
endforeach()
file(WRITE ${CRYPTO_STUB_C} "${_stub_body}")
add_library(crypto_stub SHARED ${CRYPTO_STUB_C})
set_target_properties(crypto_stub PROPERTIES OUTPUT_NAME crypto)
target_link_options(crypto_stub PRIVATE -nostdlib -Wl,-soname,libcrypto.so)

# --- The HAL service ----------------------------------------------------------
add_executable(xenoid_keymint_service
    src/keymint_service.cpp src/keymint_router.cpp src/crypto_compat.c
    src/control.cpp src/json.cpp)
add_dependencies(xenoid_keymint_service rust_ta)
target_include_directories(xenoid_keymint_service PRIVATE
    src rust/teesim-km/include)
target_link_libraries(xenoid_keymint_service PRIVATE
    keymint_aidl ${RUST_A} crypto_stub binder_ndk log)
target_link_options(xenoid_keymint_service PRIVATE
    -static-libstdc++
    # Binder/log calls newer than the min-SDK are absent from the NDK stub; let
    # them stay undefined here and resolve at runtime against the device's
    # libraries.
    -Wl,-z,undefs
    -Wl,--gc-sections)
