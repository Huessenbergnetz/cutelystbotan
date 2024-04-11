# SPDX-FileCopyrightText: (C) 2024 Matthias Fehring <https://www.huessenbergnetz.de>
#
# SPDX-License-Identifier: BSD-3-Clause

project(cutelystbotan_tests
    LANGUAGES CXX
)

find_package(Qt${QT_VERSION_MAJOR} ${QT_MINIMUM_VERSION} COMPONENTS Test)

add_executable(testcutelystbotan_exec testcutelystbotan.cpp)
add_test(NAME testcutelystbotan COMMAND testcutelystbotan_exec)
target_link_libraries(testcutelystbotan_exec CutelystBotan::Core Qt::Test)
