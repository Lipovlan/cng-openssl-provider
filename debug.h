#pragma once

#include <openssl/trace.h>

#define DEBUG_OFF 0
#define DEBUG_ERROR 1
#define DEBUG_INFO 2
#define DEBUG_TRACE 3
#define DEBUG_ALL 4

void start_tracing();

/**
 * Print string if this level is smaller or equal to global level
 * @param string String to be printed
 * @param this_level This level
 * @param global_level Global level
 */
void debug_printf(const char *string, int this_level, int global_level);