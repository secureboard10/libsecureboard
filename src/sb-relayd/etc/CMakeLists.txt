configure_file(sb-relayd@.service.in sb-relayd@.service @ONLY)
configure_file(95-secureboard.rules.in 95-secureboard.rules @ONLY)
configure_file(sb-relayd.conf.in sb-relayd.conf @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sb-relayd.conf DESTINATION etc)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sb-relayd@.service DESTINATION lib/systemd/system)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/95-secureboard.rules DESTINATION etc/udev/rules.d)
