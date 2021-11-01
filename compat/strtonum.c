
#define function strtonum
#define type long long int
#define TYPE_IS_SIGNED 1
#define TYPE_MIN LLONG_MIN
#define TYPE_MAX LLONG_MAX
#define convert_function(s, epp, base) strtoll(s, epp, base)

#include "strtotyp.c"
