cmake_minimum_required(VERSION 3.10.0)

set(ProtobufCGitRepo "https://github.com/protobuf-c/protobuf-c.git")

message(STATUS "Protobuf_C: using bundled")

set(PROTOBUF_C_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/protobuf-c)
set(PROTOBUF_C_BUILD_DIR ${PROTOBUF_C_PREFIX}/build)
set(PROTOBUF_C_INSTALL_DIR ${PROTOBUF_C_PREFIX}/install)
set(Protobuf_C_INCLUDE_DIR ${PROTOBUF_C_INSTALL_DIR}/include)
set(PROTOBUF_C_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/protobuf-c/src/ProtobufCProject/build-cmake)
set(Protobuf_C_LIBRARY_NAME "${CMAKE_STATIC_LIBRARY_PREFIX}protobuf-c${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(Protobuf_C_LIBRARY ${PROTOBUF_C_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${Protobuf_C_LIBRARY_NAME})
if(APPLE)
    set(COREFOUNDATION_LIBRARY "-framework CoreFoundation")
    set(COREFOUNDATION_LIBRARY_SECURITY "-framework Security")
    list(APPEND PROTOBUF_C_LIBRARY ${COREFOUNDATION_LIBRARY} ${COREFOUNDATION_LIBRARY_SECURITY})
endif()

include(ExternalProject)
#set CMake options and transfer the environment to an external project

option(HIDE_LINUX_PATH "Hide protobuf linux path for croscompiling" OFF)

if(WIN32)
    set(HIDE_FLAGS
        -DCMAKE_IGNORE_PATH="/usr/include/protobuf-c"
        -DCMAKE_SYSTEM_IGNORE_PATH="/usr/include/protobuf-c"
    )
endif()

set(PROTOBUF_C_BUILD_OPTIONS
    ${HIDE_FLAGS}
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DCMAKE_FIND_DEBUG_MODE=ON
    -DBUILD_SHARED_LIBS=OFF 
    -DBUILD_PROTOC=OFF
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_INSTALL_PREFIX=${PROTOBUF_C_INSTALL_DIR}
    -DCMAKE_PREFIX_PATH=C:/Users/User/Documents/cmake-prefix;${CMAKE_PREFIX_PATH}
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
    -DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM} 
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_INSTALL_LIBDIR=${CMAKE_INSTALL_LIBDIR}
    -DOSX_FRAMEWORK=OFF
    -DBUILD_TESTS=OFF
)

include(FindGit)
find_package(Git REQUIRED)
ExternalProject_Add(ProtobufCProject
    PREFIX ${PROTOBUF_C_PREFIX}
    BINARY_DIR ${PROTOBUF_C_BUILD_DIR}
    GIT_REPOSITORY "${ProtobufCGitRepo}"
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -G${CMAKE_GENERATOR} ${PROTOBUF_C_BUILD_OPTIONS} ${PROTOBUF_C_SOURCE_DIR} 
    CMAKE_ARGS ${PROTOBUF_C_BUILD_OPTIONS}
    BUILD_BYPRODUCTS ${Protobuf_C_LIBRARY}
    UPDATE_COMMAND ""
)
add_library(bundled-protobuf-c IMPORTED STATIC)
set_property(TARGET bundled-protobuf-c PROPERTY IMPORTED_LOCATION "${Protobuf_C_LIBRARY}")
set_property(TARGET bundled-protobuf-c PROPERTY INTERFACE_LINK_LIBRARIES "${Protobuf_C_LIBRARY}")
target_include_directories(bundled-protobuf-c INTERFACE "${Protobuf_C_INCLUDE_DIR}")
add_library(Protobuf_C::Protobuf_C ALIAS bundled-protobuf-c)

message(STATUS "LIB=${Protobuf_C_LIBRARY}")
message(STATUS "HEADER=${Protobuf_C_INCLUDE_DIR}")

# bundling static libraries is quite tricky and error prone
# see https://stackoverflow.com/questions/37924383/combining-several-static-libraries-into-one-using-cmake
# and other similar topics. So instead we are going to install the bundled lib
install(FILES ${Protobuf_C_LIBRARY} DESTINATION ${CMAKE_INSTALL_LIBDIR})
