if(BUILD_SHARED_LIBS AND NOT MSVC)
    find_library(M_LIB m)
endif()
if(BUNDLED_PROTOBUF_C)
    include(${PROJECT_SOURCE_DIR}/CMakeModules/protobuf_c_bundled.cmake)
else()
    if(BUILD_SHARED_LIBS)
        find_package(Protobuf_C REQUIRED)
    else()
        find_package(Protobuf_C)
    endif()
endif()

include_directories(
    .
    curve25519/ed25519/nacl_includes
    curve25519/ed25519/additions
    curve25519/ed25519/sha512
    curve25519/ed25519
    curve25519
)

set(protobuf_SRCS
    LocalStorageProtocol.pb-c.c
    WhisperTextProtocol.pb-c.c
    OMEMO.pb-c.c
)

set(omemo_SRCS
    vpool.c
    vpool.h
    signal_protocol.c
    signal_protocol.h
    signal_protocol_types.h
    signal_protocol_internal.h
    curve.c
    curve.h
    hkdf.c
    hkdf.h
    ratchet.c
    ratchet.h
    protocol.c
    protocol.h
    session_state.c
    session_state.h
    session_record.c
    session_record.h
    session_pre_key.c
    session_pre_key.h
    session_builder.c
    session_builder.h
    session_builder_internal.h
    session_cipher.c
    session_cipher.h
    key_helper.c
    key_helper.h
    sender_key.c
    sender_key.h
    sender_key_state.c
    sender_key_state.h
    sender_key_record.c
    sender_key_record.h
)

add_subdirectory(curve25519)

add_library(omemo-c
    ${protobuf_SRCS}
    ${omemo_SRCS}
    $<TARGET_OBJECTS:curve25519>
)

if(BUILD_SHARED_LIBS)
    if(NOT MSVC)
        target_link_libraries(omemo-c ${M_LIB})
    endif()
    target_link_libraries(omemo-c Protobuf_C::Protobuf_C)
    set_target_properties(omemo-c PROPERTIES
        VERSION ${OMEMO_C_VERSION}
        SOVERSION ${OMEMO_C_VERSION_MAJOR}
    )
else()
    target_include_directories(omemo-c PRIVATE ${Protobuf_C_INCLUDE_DIR})
endif()

if(BUNDLED_PROTOBUF_C)
    add_dependencies(omemo-c ProtobufCProject)
    target_link_libraries(omemo-c Protobuf_C)
endif()

INSTALL(
    FILES
    signal_protocol.h
    signal_protocol_types.h
    curve.h
    hkdf.h
    ratchet.h
    protocol.h
    session_state.h
    session_record.h
    session_pre_key.h
    session_builder.h
    session_cipher.h
    key_helper.h
    sender_key.h
    sender_key_state.h
    sender_key_record.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/omemo
)

INSTALL(TARGETS omemo-c EXPORT ${PROJECT_NAME}-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

if(GENERATE_PKGCONFIG)
    # see https://github.com/jupp0r/prometheus-cpp/issues/587
    if(IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
        set(OMEMO_C_PKGCONFIG_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}")
    else()
        set(OMEMO_C_PKGCONFIG_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
    endif()

    if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
        set(OMEMO_C_PKGCONFIG_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
    else()
        set(OMEMO_C_PKGCONFIG_LIBDIR "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
    endif()

    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/lib${PROJECT_NAME}.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.pc @ONLY)

    INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.pc DESTINATION "${INSTALL_PKGCONFIG_DIR}")
endif()


export(EXPORT ${PROJECT_NAME}-targets
  FILE "${CMAKE_CURRENT_BINARY_DIR}/cmake/${PROJECT_NAME}/${PROJECT_NAME}-targets.cmake"
  NAMESPACE ${PROJECT_NAME}::
)


set(ConfigPackageLocation ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
install(
    EXPORT ${PROJECT_NAME}-targets
    NAMESPACE ${PROJECT_NAME}::
    FILE ${PROJECT_NAME}-targets.cmake
    DESTINATION "${ConfigPackageLocation}"
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}-config.cmake.in"
    ${PROJECT_NAME}-config.cmake
    INSTALL_DESTINATION "${ConfigPackageLocation}"
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
    PATH_VARS CMAKE_INSTALL_INCLUDEDIR
)
install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
)
