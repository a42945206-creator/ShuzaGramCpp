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
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

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
  src/store/postgres/user_lock.cpp
  src/store/postgres/auth_key_store.cpp
  src/store/postgres/authorization_store.cpp
  src/store/postgres/temp_auth_key_store.cpp
)
target_include_directories(shuzagram_store_postgres PUBLIC include)
target_link_libraries(shuzagram_store_postgres PUBLIC shuzagram_domain PkgConfig::LIBPQXX
                                                        nlohmann_json::nlohmann_json OpenSSL::Crypto)
target_compile_options(shuzagram_store_postgres PRIVATE -Wall -Wextra)

add_library(shuzagram_mtproto
  src/mtproto/crypto/aes_ige.cpp
  src/mtproto/crypto/rsa.cpp
  src/mtproto/crypto/rsa_pad.cpp
  src/mtproto/crypto/random.cpp
  src/mtproto/crypto/dh.cpp
  src/mtproto/server_exchange.cpp
  src/mtproto/transport/full_codec.cpp
  src/mtproto/crypto/message_cipher.cpp
  src/mtproto/crypto/kdf_v1.cpp
  src/mtproto/crypto/bind.cpp
  src/net/tcp_socket.cpp
  src/net/tcp_listener.cpp
  src/mtproto/tcp_handshake_server.cpp
  src/mtproto/session.cpp
)
target_include_directories(shuzagram_mtproto PUBLIC include)
find_package(Threads REQUIRED)
target_link_libraries(shuzagram_mtproto PUBLIC OpenSSL::Crypto Threads::Threads)
target_compile_options(shuzagram_mtproto PRIVATE -Wall -Wextra)

# The auth.bindTempAuthKey business logic: the one piece that needs both
# crypto (shuzagram_mtproto) and the store interfaces (header-only; a
# concrete implementation, e.g. shuzagram_store_postgres, is linked in by
# whichever executable actually wires this up).
add_library(shuzagram_auth
  src/auth/bind_temp_auth_key.cpp
  src/auth/sign_in.cpp
  src/store/memory/code_store.cpp
)
target_include_directories(shuzagram_auth PUBLIC include)
target_link_libraries(shuzagram_auth PUBLIC shuzagram_mtproto shuzagram_domain)
target_compile_options(shuzagram_auth PRIVATE -Wall -Wextra)

enable_testing()
add_subdirectory(tests)
add_subdirectory(cmd/shuzagram_server)
