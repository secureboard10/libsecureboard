add_executable(sb-relayd
  sb-relayd.c
  threads.c
  udev.c
  unix-socket.c
  inet-socket.c)

include(FindPkgConfig)
find_package(PkgConfig REQUIRED)

pkg_check_modules(UDEV REQUIRED libudev)
target_link_libraries(sb-relayd ${UDEV_LIBRARIES})
target_compile_options(sb-relayd PUBLIC ${UDEV_CFLAGS_OTHER})
target_include_directories(sb-relayd PUBLIC ${UDEV_INCLUDE_DIRS})

pkg_check_modules(HIDAPI REQUIRED hidapi-hidraw)
target_link_libraries(sb-relayd ${HIDAPI_LIBRARIES})
target_compile_options(sb-relayd PUBLIC ${HIDAPI_CFLAGS_OTHER})
target_include_directories(sb-relayd PUBLIC ${HIDAPI_INCLUDE_DIRS})

pkg_check_modules(LIBCONFIG REQUIRED libconfig)
target_link_libraries(sb-relayd ${LIBCONFIG_LIBRARIES})
target_compile_options(sb-relayd PUBLIC ${LIBCONFIG_CFLAGS_OTHER})
target_include_directories(sb-relayd PUBLIC ${LIBCONFIG_INCLUDE_DIRS})

target_compile_options(sb-relayd PRIVATE "-Wall" "-Werror" "-std=gnu99" "-D_GNU_SOURCE" "-O3")
target_compile_definitions(sb-relayd PRIVATE LICENSE=${LICENSE})
target_link_libraries(sb-relayd "pthread")

add_subdirectory(etc)

install(TARGETS sb-relayd DESTINATION sbin)
