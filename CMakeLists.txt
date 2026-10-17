cmake_minimum_required(VERSION 3.16)
project(grantry
    VERSION 0.1.0
    DESCRIPTION "Identity, access and entitlements for native C++ applications"
    HOMEPAGE_URL "https://grantry.dev"
    LANGUAGES CXX)

#
# The dependency policy, stated in the build rather than only in the README.
#
# On Windows there are NO third-party dependencies: WinHTTP, BCrypt and DPAPI
# are all in-box, so a customer shipping this library ships no extra DLL beside
# their executable. On POSIX the system libraries are libcurl and OpenSSL, which
# is the same argument reaching a different answer.
#

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

#
# ⚠️ TESTS AND INSTALL RULES DEFAULT TO OFF WHEN THIS IS SOMEBODY ELSE'S
# SUBDIRECTORY. A consumer who vendors the SDK with add_subdirectory wants the
# library, not a test executable in their build tree and our headers in their
# install. They can still turn either on. (PROJECT_IS_TOP_LEVEL needs CMake
# 3.21; this comparison is the same test on 3.16.)
#
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(GRANTRY_TOP_LEVEL ON)
else()
    set(GRANTRY_TOP_LEVEL OFF)
endif()

option(GRANTRY_BUILD_TESTS "Build the test suite" ${GRANTRY_TOP_LEVEL})
option(GRANTRY_INSTALL "Generate install rules and the grantry CMake package" ${GRANTRY_TOP_LEVEL})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(grantry STATIC
    src/json.cpp
    src/encoding.cpp
    src/crypto.cpp
    src/verifier.cpp
    src/client.cpp
    src/loopback.cpp
    src/platform_windows.cpp
    src/platform_posix.cpp
)
# The name an installed package exports, so add_subdirectory and find_package
# consumers write the same target_link_libraries line.
add_library(grantry::grantry ALIAS grantry)

# The public header uses std::optional, so C++17 is a requirement of every
# consumer, not only of this library's own sources.
target_compile_features(grantry PUBLIC cxx_std_17)

# One version: Version(), the User-Agent and X-Grantry-Sdk all read this.
target_compile_definitions(grantry PRIVATE GRANTRY_VERSION="${PROJECT_VERSION}")

set_target_properties(grantry PROPERTIES
    # A static library that ends up inside a shared one — a plugin, or an
    # application's own DLL — has to be position-independent on Linux.
    POSITION_INDEPENDENT_CODE ON
    VERSION ${PROJECT_VERSION}
)

target_include_directories(grantry
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(WIN32)
    # ws2_32 for the one socket the library opens itself: the loopback listener a
    # redirect sign-in comes back to (src/loopback.cpp). WinHTTP is still the
    # transport for everything else. advapi32 for the machine SID: the sources
    # name it with #pragma comment, which MinGW ignores.
    target_link_libraries(grantry PUBLIC winhttp bcrypt crypt32 shell32 ole32 ws2_32 advapi32)
    # Suppress the CRT's "use the _s variants" noise. The uses here are bounded
    # and checked; rewriting them to Microsoft-only functions would break the
    # POSIX build for no safety gain.
    target_compile_definitions(grantry PRIVATE _CRT_SECURE_NO_WARNINGS)
    if(MSVC)
        #
        # /EHsc is set explicitly rather than relied upon.
        #
        # CMake puts it in the default CMAKE_CXX_FLAGS, so a standalone build of
        # this library picks it up and nobody notices. A consumer who vendors us
        # with add_subdirectory does not always inherit those defaults, and the
        # library's own translation units then compile with a warning that the
        # standard library's unwind semantics are unavailable. The library is
        # written to work without exceptions — that is why it returns Result<T>
        # rather than throwing — but it still USES std::string and std::ofstream,
        # whose headers reference the machinery.
        #
        # ⚠️ THIS DOES NOT FORCE EXCEPTIONS ON THE CONSUMER. It applies to this
        # target's own sources; an application built with /EHs-c- still links.
        #
        target_compile_options(grantry PRIVATE /W4 /permissive- /EHsc)
    endif()
else()
    #
    # ⚠️ PRIVATE, BUT A STATIC LIBRARY STILL HANDS THEM ON. Its consumers link
    # libcurl and libcrypto themselves, which CMake arranges in a build tree
    # and the installed package's config file arranges with find_dependency.
    #
    # On macOS libcurl is the system's; OpenSSL is not (the system ships
    # LibreSSL without headers), so a Homebrew or vcpkg OpenSSL 1.1.1 or 3.x
    # is needed: -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3).
    #
    find_package(CURL REQUIRED)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(grantry PRIVATE CURL::libcurl OpenSSL::Crypto)
    target_compile_options(grantry PRIVATE -Wall -Wextra)
endif()

if(GRANTRY_BUILD_TESTS)
    enable_testing()

    add_executable(grantry_tests
        tests/main.cpp
    )
    target_link_libraries(grantry_tests PRIVATE grantry)
    target_include_directories(grantry_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

    if(WIN32)
        target_compile_definitions(grantry_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
        # The tests open loopback sockets of their own: to prove the start-up
        # probe leaves the process, and to stand in for the API and for the
        # browser a redirect sign-in returns through.
        target_link_libraries(grantry_tests PRIVATE ws2_32)
    else()
        find_package(OpenSSL REQUIRED)
        target_link_libraries(grantry_tests PRIVATE OpenSSL::Crypto)
    endif()

    add_test(NAME grantry_tests COMMAND grantry_tests)
endif()

#
# The conformance driver: one SDK call per process, for the cross-SDK harness in
# apps/api/conformance. Off by default — it is a test tool, not something a
# customer's build should ever produce — and it uses only the public header, so
# it proves what an application can actually reach.
#
option(GRANTRY_BUILD_CONFORMANCE "Build the cross-SDK conformance driver" OFF)
if(GRANTRY_BUILD_CONFORMANCE)
    add_executable(grantry_conformance conformance/driver.cpp)
    target_link_libraries(grantry_conformance PRIVATE grantry)
endif()

#
# find_package(grantry CONFIG) support:
#
#   find_package(grantry 0.1 CONFIG REQUIRED)
#   target_link_libraries(your_app PRIVATE grantry::grantry)
#
# ⚠️ SameMinorVersion WHILE THE MAJOR IS ZERO. Before 1.0 a minor release may
# change the ABI — this is a static library of C++ classes — so 0.2 must not
# satisfy a request for 0.1.
#
if(GRANTRY_INSTALL)
    set(GRANTRY_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/grantry)

    install(TARGETS grantry EXPORT grantry-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(EXPORT grantry-targets
        NAMESPACE grantry::
        DESTINATION ${GRANTRY_CMAKE_DIR})

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/grantry-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/grantry-config.cmake
        INSTALL_DESTINATION ${GRANTRY_CMAKE_DIR})
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/grantry-config-version.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMinorVersion)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/grantry-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/grantry-config-version.cmake
        DESTINATION ${GRANTRY_CMAKE_DIR})

    install(FILES LICENSE README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
endif()
