# CMake for src
add_library(irc_core STATIC
  protocol_parse.c
  ircv3_tags.c
  federation_handshake.c
  core/message.c
  core/connection.c
  core/server.c
  core/poll_loop.c
)

target_link_libraries(irc_core PRIVATE pthread)

# Expose src/ headers to anything linking irc_core (tests, benchmarks).
target_include_directories(irc_core PUBLIC ${PROJECT_SOURCE_DIR}/src)

# Executable for federated node
add_executable(irc-serve node_main.c)
target_link_libraries(irc-serve PRIVATE irc_core)

install(TARGETS irc-serve RUNTIME DESTINATION bin)
