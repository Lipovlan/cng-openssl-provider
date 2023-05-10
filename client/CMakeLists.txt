add_executable(client client.c ../debug.c)
target_link_libraries(client PUBLIC cng_provider ${LINK_LIBS})