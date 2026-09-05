# CMake for src
add_library(irc_core STATIC
  server.c
  protocol.c
  federation.c
)

target_link_libraries(irc_core PRIVATE pthread)

# Executable for federated node
add_executable(irc-serve node_main.c)
target_link_libraries(irc-serve PRIVATE irc_core)
