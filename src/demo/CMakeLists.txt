add_executable(sb-tool
  secureboard.c)

include(FindPkgConfig)
find_package(PkgConfig REQUIRED)

pkg_check_modules(EVDEV REQUIRED libevdev)
target_link_libraries(sb-tool ${EVDEV_LIBRARIES})
target_compile_options(sb-tool PUBLIC ${EVDEV_CFLAGS_OTHER})
target_include_directories(sb-tool PUBLIC ${EVDEV_INCLUDE_DIRS})
target_compile_definitions(sb-tool
  PUBLIC
  USE_EVDEV=1
  EVDEV_VERBOSE=0)
target_sources(sb-tool PUBLIC evdev.c)

get_property(secureboard_INCLUDE_DIRECTORIES TARGET secureboard PROPERTY INCLUDE_DIRECTORIES)
target_compile_options(sb-tool PRIVATE "-Wall" "-Werror" "-std=gnu99" "-D_GNU_SOURCE" "-O3")

target_include_directories(sb-tool PUBLIC ${secureboard_INCLUDE_DIRECTORIES})
target_link_libraries(sb-tool secureboard)
target_link_libraries(sb-tool ${OPENSSL_LDFLAGS})
target_link_libraries(sb-tool "pthread" "dl")

install(TARGETS sb-tool DESTINATION bin)
