cmake_minimum_required(VERSION 3.5)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
project(omemo-c)

if(POLICY CMP0042)
	cmake_policy(SET CMP0042 NEW)
endif()

set(OMEMO_C_VERSION_MAJOR 0)
set(OMEMO_C_VERSION_MINOR 5)
set(OMEMO_C_VERSION_PATCH 0)
set(OMEMO_C_VERSION ${OMEMO_C_VERSION_MAJOR}.${OMEMO_C_VERSION_MINOR}.${OMEMO_C_VERSION_PATCH})

include(GNUInstallDirs)

option(GENERATE_PKGCONFIG "Generate and install pkg-config files" ${UNIX})
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_LIBDIR}/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
set(BUILD_WITH_PROTOBUF "auto" CACHE STRING "How to find/link with protobuf")
set_property(CACHE BUILD_WITH_PROTOBUF PROPERTY STRINGS auto static bundled)
# auto - try to find any system protobuf-c library
# static - try to find static system protobuf-c library
# bundled - download and build protobuf-c from github

include(CheckSymbolExists)
include(CheckCCompilerFlag)
include(TestBigEndian)

CHECK_SYMBOL_EXISTS(memset_s "string.h" HAVE_MEMSET_S)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
	CHECK_SYMBOL_EXISTS(SecureZeroMemory "Windows.h;WinBase.h" HAVE_SECUREZEROMEMORY)
endif(CMAKE_SYSTEM_NAME MATCHES "Windows")

if(BUILD_TESTING)
	enable_testing()
endif(BUILD_TESTING)

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fmessage-length=0 -Wall -Wmissing-field-initializers -Wno-missing-braces -Wparentheses")
endif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")

if(CMAKE_COMPILER_IS_GNUCC)
	CHECK_C_COMPILER_FLAG("-Wsign-conversion" GCC_WARN_SIGN_CONVERSION)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsign-compare")
        if(GCC_WARN_SIGN_CONVERSION)
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsign-conversion")
        endif(GCC_WARN_SIGN_CONVERSION)
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wswitch -Wunused-variable -Wunused-value -Wshadow -Wint-conversion -Wpointer-sign -Wprotocol -Wshorten-64-to-32")
endif(CMAKE_C_COMPILER_ID MATCHES "Clang")

if(HAVE_MEMSET_S)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_MEMSET_S=1")
endif(HAVE_MEMSET_S)

TEST_BIG_ENDIAN(WORDS_BIGENDIAN)
if(WORDS_BIGENDIAN)
	ADD_DEFINITIONS(-DWORDS_BIGENDIAN)
endif(WORDS_BIGENDIAN)

if(COVERAGE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
        set(LINK_FLAGS "${LINK_FLAGS} -fprofile-arcs -ftest-coverage")

	add_custom_command(OUTPUT run_coverage
			COMMAND ctest
			COMMAND lcov -q --capture --directory src --output-file coverage.info.total
			COMMAND lcov -q --remove coverage.info.total 'vpool.*' 'ut*.h' '*.pb-c.*' 'protobuf-c/*' 'curve25519/*' --output-file coverage.info
			COMMAND genhtml -q coverage.info --output-directory coverage
			COMMENT Collecting and creating coverage information
	)
	add_custom_target( coverage DEPENDS run_coverage )
endif(COVERAGE)

add_subdirectory(src)

if(BUILD_TESTING)
	add_subdirectory(tests)
endif(BUILD_TESTING)

# this hack makes files visible in the project view of QtCreator
add_custom_target(useful_files ALL
    SOURCES
    src/lib${PROJECT_NAME}.pc.in
    src/${PROJECT_NAME}-config.cmake.in
    CMakeModules/BlackBerry.toolchain.cmake
    CMakeModules/FindCheck.cmake
    CMakeModules/FindProtobuf_C.cmake
    CMakeModules/iOS.toolchain.cmake
    CMakeModules/protobuf_c_bundled.cmake
)

