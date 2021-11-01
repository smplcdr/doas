
#define function strtounum
#define type unsigned long long int
#define TYPE_IS_SIGNED 0
#define TYPE_MAX ULLONG_MAX
#define convert_function(s, epp, base) strtoull(s, epp, base)

#include "strtotyp.c"
