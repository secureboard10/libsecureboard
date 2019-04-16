cmake_minimum_required (VERSION 3.7)

set(LICENSE "\"${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt\"")

file(STRINGS VERSION version)
foreach(kvp ${version})
  string(STRIP kvp ${kvp})
  # Find variable name
  string(REGEX MATCH "^[^=]+" Name ${kvp})
  # Find the value
  string(REPLACE "${Name}=" "" Value ${kvp})
  # Set the variable
  set(${Name} ${Value})
endforeach()

project(libsecureboard VERSION ${PROJECT_NUMBER})

message("Configure ${PROJECT_NAME} build for version ${PROJECT_VERSION}")

find_package(PkgConfig)

set(ENV{PKG_CONFIG_PATH} "${CMAKE_SOURCE_DIR}/external/.build/openssl/lib/pkgconfig")

pkg_check_modules(OPENSSL REQUIRED openssl=1.1.1a-tds)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPENSSL_CFLAGS} -O3")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVERSION=\"${PROJECT_VERSION}\"")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVERSION_MAJOR=${PROJECT_VERSION_MAJOR}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVERSION_MINOR=${PROJECT_VERSION_MINOR}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVERSION_PATCH=${PROJECT_VERSION_PATCH}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVERSION_TWEAK=${PROJECT_VERSION_TWEAK}")

install(FILES ca/client-cert/client-root-ca.pem DESTINATION share/libsecureboard/ca)
install(FILES ca/client-cert/bob.pem DESTINATION share/libsecureboard/ca)
install(FILES ca/client-cert/alice.pem DESTINATION share/libsecureboard/ca)
install(FILES ca/client-cert/keys/bob-key.pem DESTINATION share/libsecureboard/priv-keys)
install(FILES ca/client-cert/keys/alice-key.pem DESTINATION share/libsecureboard/priv-keys)
install(SCRIPT "post_install.cmake")

add_subdirectory(src)

