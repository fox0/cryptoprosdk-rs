//#[cfg(all(target_family = "unix", target_pointer_width = "64"))]
#define UNIX 1
#define HAVE_LIMITS_H 1
#define HAVE_STDINT_H 1
#define SIZEOF_VOID_P 8

#include <WinCryptEx.h>
#include <cades.h>
