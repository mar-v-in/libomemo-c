#=============================================================================
# Copyright 2024 Psi+ Project, Vitaly Tonkacheyev
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#=============================================================================

if( Protobuf_C_INCLUDE_DIR AND Protobuf_C_LIBRARY )
    # in cache already
    set(Protobuf_C_FIND_QUIETLY TRUE)
endif()

if( UNIX AND NOT( APPLE OR CYGWIN ) )
    find_package( PkgConfig QUIET )
    pkg_check_modules( PROTOBUF_C QUIET protobuf-c )
    if( PC_PROTOBUF_C_FOUND )
        set( PROTOBUF_C_DEFINITIONS ${PC_PROTOBUF_C_CFLAGS} ${PC_PROTOBUF_C_CFLAGS_OTHER} )
        add_library(Protobuf_C::Protobuf_C ALIAS PkgConfig::PROTOBUF_C)
    endif()
endif()

if (NOT(PC_Protobuf_C_FOUND))
    set( Protobuf_C_ROOT "" CACHE STRING "Path to protobuf-c library" )

    find_path(
        Protobuf_C_INCLUDE_DIR protobuf-c.h
        HINTS
        ${Protobuf_C_ROOT}/include
        ${PC_PROTOBUF_C_INCLUDEDIR}
        ${PC_PROTOBUF_C_INCLUDE_DIRS}
        PATH_SUFFIXES
        ""
        protobuf-c
    )

    set(PROTOBUF_LIB_DIRS
        ${PC_PROTOBUF_C_LIBDIR}
        ${PC_PROTOBUF_C_LIBRARY_DIRS}
        ${Protobuf_C_ROOT}/lib)
    if(STATIC_PROTOBUF_C)
        message(STATUS "Looking for static Protobuf-C")
        set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
        set(Protobuf_C_NAMES
            protobuf-c.lib
            libprotobuf-c.a
        )
    else()
        message(STATUS "Looking for any Protobuf-C")
        set(Protobuf_C_NAMES
            protobuf-c
            libprotobuf-c
        )
        list(APPEND PROTOBUF_LIB_DIRS ${Protobuf_C_ROOT}/bin)
    endif()
    find_library(
        Protobuf_C_LIBRARY protobuf-c
        NAMES ${Protobuf_C_NAMES}
        HINTS
        ${PROTOBUF_LIB_DIRS}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(
        Protobuf_C
        DEFAULT_MSG
        Protobuf_C_LIBRARY
        Protobuf_C_INCLUDE_DIR
    )

    if( Protobuf_C_FOUND )
        set( Protobuf_C_LIBRARIES ${PROTOBUF_C_LIBRARY} )
        set( PProtobuf_INCLUDE_DIRS ${PROTOBUF_C_INCLUDE_DIR} )
        add_library(protobuf-c IMPORTED UNKNOWN)
        set_property(TARGET protobuf-c PROPERTY
                     IMPORTED_LOCATION "${Protobuf_C_LIBRARY}")
        add_library(Protobuf_C::Protobuf_C ALIAS protobuf-c)
        target_include_directories(protobuf-c INTERFACE "${Protobuf_C_INCLUDE_DIR}")
    endif()

    mark_as_advanced( Protobuf_C_INCLUDE_DIR Protobuf_C_LIBRARY )
endif()
