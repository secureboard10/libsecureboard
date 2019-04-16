add_library(secureboard
  STATIC
  secureboard.c
  connection.c
  usb_encap.c)

target_include_directories(secureboard PUBLIC include)
target_compile_options(secureboard PRIVATE "-Wall" "-Werror" "-DALLOW_LIB_SECUREBOARD_INTERNAL" "-O3")
target_compile_definitions(secureboard PRIVATE LICENSE=${LICENSE})

install(TARGETS secureboard
  DESTINATION lib)
install(DIRECTORY include DESTINATION . FILES_MATCHING PATTERN "*.h")
