/* Public domain.  */

#include <string.h>

void explicit_bzero(void *buf, size_t len)
{
#if defined (__GNUC__) && !defined(__clang__)
	memset(buf, '\0', len);
	/* Compiler barrier.  */
	__asm__ __volatile__("" ::: "memory");
#elif defined(__clang__)
	memset(buf, '\0', len);
	/* Compiler barrier.  */
	/* With asm ("" ::: "memory") LLVM analyzes uses of 's' and finds that the
	   whole thing is dead and eliminates it.  Use 'g' to work around this
	   problem.  See <https://bugs.llvm.org/show_bug.cgi?id=15495#c11>.  */
	__asm__ __volatile__("" : : "g"(buf) : "memory");
#else
	/* Invoke memset through a volatile function pointer.  This defeats compiler
	   optimizations.  */
	void *(*const volatile volatile_memset)(void *, int, size_t) = memset;
	(void)volatile_memset(buf, '\0', len);
#endif
}
