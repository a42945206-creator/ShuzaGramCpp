cmake_minimum_required(VERSION 3.22)
project(shuzagram LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPQXX REQUIRED IMPORTED_TARGET libpqxx)
find_package(nlohmann_json REQUIRED)

# libphonenumber (Debian's libphonenumber-dev) ships no pkg-config file, so
# it's located and linked by name instead.
find_library(PHONENUMBER_LIB NAMES phonenumber REQUIRED)
find_path(PHONENUMBER_INCLUDE_DIR NAMES phonenumbers/phonenumberutil.h REQUIRED)

add_library(shuzagram_domain
  src/domain/phone.cpp
)
target_include_directories(shuzagram_domain PUBLIC include PRIVATE ${PHONENUMBER_INCLUDE_DIR})
target_link_libraries(shuzagram_domain PUBLIC ${PHONENUMBER_LIB})
target_compile_options(shuzagram_domain PRIVATE -Wall -Wextra)

add_library(shuzagram_store_postgres
  src/store/postgres/user_store.cpp
  src/store/postgres/auth_identity_lock.cpp
  src/store/postgres/auth_key_store.cpp
  src/store/postgres/authorization_store.cpp
)
target_include_directories(shuzagram_store_postgres PUBLIC include)
target_link_libraries(shuzagram_store_postgres PUBLIC shuzagram_domain PkgConfig::LIBPQXX
                                                        nlohmann_json::nlohmann_json)
target_compile_options(shuzagram_store_postgres PRIVATE -Wall -Wextra)

enable_testing()
add_subdirectory(tests)
