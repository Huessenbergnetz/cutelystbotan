# SPDX-FileCopyrightText: (C) 2024 Matthias Fehring <https://www.huessenbergnetz.de>
#
# SPDX-License-Identifier: BSD-3-Clause

cmake_minimum_required(VERSION 3.16)

project(cutelystbotan
    VERSION 0.0.1
    DESCRIPTION "Authentication credential provider for Cutelyst using Botan for password hashing."
    HOMEPAGE_URL "https://github.com/Huessenbergnetz/cutelystbotan"
    LANGUAGES CXX
)

include(GNUInstallDirs)
include(GenerateExportHeader)
include(CMakePackageConfigHelpers)

set(CUTELYST_VERSION_MAJOR 4)
set(QT_VERSION_MAJOR 6)
set(QT_MINIMUM_VERSION 6.2)

find_package(Qt${QT_VERSION_MAJOR} ${QT_MINIMUM_VERSION} COMPONENTS Core Network REQUIRED)
find_package(Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR} 4.0.0 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(Botan REQUIRED IMPORTED_TARGET botan-2)

set(CUTELYSTBOTAN_API_LEVEL "0")

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

# Auto generate moc files
set(CMAKE_AUTOMOC ON)

# As moc files are generated in the binary dir, tell CMake
# to always look for includes there:
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_INCLUDE_CURRENT_DIR_IN_INTERFACE ON)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

option(BUILD_SHARED_LIBS "Build in shared lib mode" ON)
option(ENABLE_TESTS "Build the unit tests" OFF)
option(ENABLE_MAINTAINER_CFLAGS "Enable maintainer CFlags" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (ENABLE_TESTS)
    enable_testing()
endif (ENABLE_TESTS)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "cutelystbotan default install prefix" FORCE)
endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}BotanConfigVersion.cmake
    VERSION ${cutelybotan_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/CutelystBotan-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}BotanConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}BotanConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan
    COMPONENT development
)

install(EXPORT CutelystBotanTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Botan
    FILE Cutelyst${CUTELYST_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}BotanTargets.cmake
    NAMESPACE CutelystBotan::
    COMPONENT development
)

add_subdirectory(CutelystBotan)
if (ENABLE_TESTS)
    add_subdirectory(tests)
endif (ENABLE_TESTS)
