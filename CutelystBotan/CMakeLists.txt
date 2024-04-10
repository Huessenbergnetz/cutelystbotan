# SPDX-FileCopyrightText: (C) 2024 Matthias Fehring <https://www.huessenbergnetz.de>
#
# SPDX-License-Identifier: BSD-3-Clause

set(cutelystbotan_SRC
    credentialbotan.cpp
)

set(cutelystbotan_HEADERS
    ${CMAKE_CURRENT_BINARY_DIR}/cutelystbotan_export.h
    credentialbotan.h
)

add_library(Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan
    ${cutelystbotan_SRC}
    ${cutelystbotan_HEADERS}
)

add_library(CutelystBotan::Core ALIAS Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan)

generate_export_header(Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan BASE_NAME cutelystbotan)

target_compile_features(Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan
    PUBLIC
        cxx_std_20
)

target_include_directories(Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/cutelyst${CUTELYST_VERSION_MAJOR}botan-qt${QT_VERSION_MAJOR}>
)

target_compile_definitions(Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan
    PRIVATE
        QT_NO_KEYWORDS
        QT_NO_CAST_TO_ASCII
        QT_NO_CAST_FROM_ASCII
        QT_STRICT_ITERATORS
        QT_NO_URL_CAST_FROM_STRING
        QT_NO_CAST_FROM_BYTEARRAY
        QT_USE_QSTRINGBUILDER
        QT_NO_SIGNALS_SLOTS_KEYWORDS
        QT_USE_FAST_OPERATOR_PLUS
        QT_DISABLE_DEPRECATED_BEFORE=0x060200
)

set_target_properties(Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan PROPERTIES
    EXPORT_NAME Core
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${cutelystbotan_HEADERS}"
)

target_link_libraries(Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan
    PUBLIC
        Cutelyst::Core
        Qt${QT_VERSION_MAJOR}::Core
)

install(TARGETS Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan
    EXPORT CutelystBotanTargets DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT runtime
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT devel
    PUBLIC_HEADER DESTINATION include/cutelyst${CUTELYST_VERSION_MAJOR}botan-qt${QT_VERSION_MAJOR}/CutelystBotan COMPONENT devel
)
