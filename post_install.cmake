

exec_program(
  "mkdir"
  ARGS -p ${DESTDIR}/share/libsecureboard/example-user-device-ca)

exec_program(
  ${CMAKE_CURRENT_SOURCE_DIR}/../script/mk_cert.sh
  ARGS
  -g -v
  -r ${DESTDIR}/share/libsecureboard/example-user-device-ca/example-root-ca
  -d ${DESTDIR}/share/libsecureboard/example-user-device-ca/example-dev-01
  -c device-01)

exec_program(
  ${CMAKE_CURRENT_SOURCE_DIR}/../script/mk_cert.sh
  ARGS
  -v
  -r ${DESTDIR}/share/libsecureboard/example-user-device-ca/example-root-ca
  -d ${DESTDIR}/share/libsecureboard/example-user-device-ca/example-dev-02
  -c device-02)

exec_program(
  ${CMAKE_CURRENT_SOURCE_DIR}/../script/mk_cert.sh
  ARGS
  -v
  -r ${DESTDIR}/share/libsecureboard/example-user-device-ca/example-root-ca
  -d ${DESTDIR}/share/libsecureboard/example-user-device-ca/example-dev-03
  -c device-03)

exec_program(
  ln
  ARGS
  -fs
  ${DESTDIR}/share/libsecureboard/example-user-device-ca/example-root-ca.pem
  ${DESTDIR}/share/libsecureboard/ca)

MESSAGE("rehash CA")
exec_program(
  "c_rehash"
  ARGS ${DESTDIR}/share/libsecureboard/ca
  OUTPUT_VARIABLE out
  RETURN_VALUE res)

if(NOT ${res} EQUAL 0)
  message(FATAL_ERROR "failed to rehash ca. c_rehash says '${out}'")
endif()

