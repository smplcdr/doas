/*
 * Copyright (c) 2021 Sergey Sushilin <sergeysushilin@protonmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _ATTRIBUTES_H
#define _ATTRIBUTES_H 1

#if  (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 8)) \
	|| defined(__clang__) || __SUNPRO_C >= 0x5110 \
	|| defined(__TINYC__) || __HP_cc >= 61000
# define __noreturn __attribute__((__noreturn__))
#else
# define __noreturn /* Nothing.  */
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96)
# define __pure __attribute__ ((__pure__))
#else
# define __pure /* Nothing.  */
#endif

#undef __const
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 95)
# define __const __attribute__((__const__))
#else
# define __const /* Nothing.  */
#endif

#if !defined(__nonnull)
# if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3) || defined(__clang__)
#  define __nonnull(params) __attribute__((__nonnull__ params))
# else
#  define __nonnull(params) /* Nothing.  */
# endif
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
# define __unused __attribute__((__unused__))
#else
# define __unused /* Nothing.  */
#endif

#undef __wur
/* Warn about unused results of certain
   function calls which can lead to problems.  */
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
# define __wur __attribute__((__warn_unused_result__))
#else
# define __wur /* Nothing.  */
#endif

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)
# define __format_printf(p1, p2) __attribute__((__format__(__gnu_printf__, p1, p2)))
#elif __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5)
# define __format_printf(p1, p2) __attribute__((__format__(__printf__, p1, p2)))
#else
# define __format_printf(p1, p2) /* Nothing.  */
#endif

#if __GNUC__ >= 11
# define __dealloc(f, n) __attribute__ ((__malloc__ (f, n)))
# define __malloc __attribute__ ((__malloc__))
#elif __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96)
# define __dealloc(f, n) /* Nothing.  */
# define __malloc __attribute__ ((__malloc__))
#else
# define __dealloc(f, n) /* Nothing.  */
# define __malloc /* Nothing.  */
#endif

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
# define __alloc_size(params) __attribute__((__alloc_size__ params))
#else
# define __alloc_size(params) /* Nothing.  */
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
# define __packed __attribute__((__packed__))
#else
# define __packed /* Nothing.  */
#endif

#if (__GNUC__ >= 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)) && !defined(__PCC__)
# define __returns_nonnull __attribute__((__returns_nonnull__))
#else
# define __returns_nonnull /* Nothing.  */
#endif

#if __GNUC__ >= 7
# define fallthrough __attribute__((__fallthrough__))
#else
# define fallthrough ((void)0)
#endif

#endif /* _ATTRIBUTES_H */
