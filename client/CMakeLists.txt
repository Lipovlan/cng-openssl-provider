add_executable(client client.c ../debug.c)
target_link_libraries(client PUBLIC OpenSSL::SSL OpenSSL::Crypto)
