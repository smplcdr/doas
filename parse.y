/* $OpenBSD: parse.y,v 1.26 2017/01/02 01:40:20 tedu Exp $ */
/*
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
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

%{

#include <err.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>

#include "compat.h"
#include "rule.h"
#include "wrappers.h"
#include "yystype.h"

extern FILE *yyin;

struct rule *rules;
size_t nrules = 0;
static size_t maxrules = 0;

static u_int parse_errors = 0;

static void yyerror(char const *fmt, ...) __nonnull((1)) __format_printf(1, 2);
#if !HAVE_LEX && !HAVE_FLEX
static int yylex(void);
#else
extern int yylex(void);
#endif

void free_rules(void);
static void add_rule(struct rule const *rule) __nonnull((1));

struct passwd *original_pw = NULL, *target_pw = NULL;

extern char **environ;

#define assign_option(_0, _1, _2, option, name, value)				\
	do {									\
		if (_2.name != value) {						\
			if (_0.name != value)					\
				yyerror(option" option is already set");	\
			else							\
				_0.name = _2.name;				\
		}								\
	} while (0)

%}

%token TOK_PERMIT TOK_DENY TOK_FROM TOK_AS TOK_EXECUTE TOK_ELLIPSIS
%token TOK_INHERITENV TOK_KEEPENV TOK_SETENV TOK_UNSETENV
%token TOK_PERSIST TOK_NOPASS TOK_NOLOG
%token TOK_STRING TOK_NUMBER TOK_NAME
%token TOK_UNKNOWN ','

%left ','

%%

grammar:	/* Empty.  */
		| grammar '\n'
		| grammar rule '\n'
		| error '\n' {
			YYERROR;
		} | TOK_UNKNOWN '\n' {
			YYERROR;
		} ;

rule:		TOK_PERMIT options ident target argv {
			struct rule r = {
				.permit		= true,
				.env		= $2.env,
				.keepenvlist	= $2.keepenvlist,
				.setenvlist	= $2.setenvlist,
				.unsetenvlist	= $2.unsetenvlist,
				.persist_time	= $2.persist_time,
				.inheritenv	= $2.inheritenv,
				.nopass		= $2.nopass,
				.nolog		= $2.nolog,
				.ident.pw	= $3.ident.pw,
				.ident.gr	= $3.ident.gr,
				.target.pw	= $4.target.pw,
				.argc		= $5.argc,
				.argv		= $5.argv
			};

			add_rule(&r);
		} | TOK_DENY ident target argv {
			struct rule r = {
				.permit		= false,
				.ident.pw	= $2.ident.pw,
				.ident.gr	= $2.ident.gr,
				.target.pw	= $3.target.pw,
				.argv		= $4.argv
			};

			warnx("try to use 'permit' rather than 'deny',"
			      "since last is not secure enough");

		      add_rule(&r);
		} ;

option:		persist {
			$$ = (YYSTYPE){ .persist_time = $1.persist_time };
		} | TOK_NOPASS {
			$$ = (YYSTYPE){ .nopass = true };
		} | TOK_NOLOG {
			$$ = (YYSTYPE){ .nolog = true };
		} ;
options:	/* None.  */ {
			$$.env = createenv();
			defaultenv($$.env, original_pw, target_pw);
			$$.keepenvlist = NULL;
			$$.setenvlist = NULL;
			$$.unsetenvlist = NULL;
			$$.persist_time = 0;
			$$.inheritenv = false;
			$$.nopass = false;
			$$.nolog = false;
		} | options TOK_KEEPENV '{' strlist '}' {
			$$ = $1;
			assign_option($$, $1, $2, "keepenv", keepenvlist, NULL);
			if (keepenv($$.env, $4.strlist) != 0)
				parse_errors++;
			$$.keepenvlist = $4.strlist;
		} | options TOK_SETENV '{' strlist '}' {
			$$ = $1;
			assign_option($$, $1, $2, "setenv", setenvlist, NULL);
			if (fillenv($$.env, $4.strlist) != 0)
				parse_errors++;
			$$.setenvlist = $4.strlist;
		} | options TOK_UNSETENV '{' strlist '}' {
			$$ = $1;
			assign_option($$, $1, $2, "unsetenv", unsetenvlist, NULL);
			if (unfillenv($$.env, $4.strlist) != 0)
				parse_errors++;
			$$.unsetenvlist = $4.strlist;
		} | options TOK_INHERITENV {
			$$ = $1;
			assign_option($$, $1, $2, "inheritenv", inheritenv, false);
			inheritenv($$.env);
			$$.inheritenv = true;
		} | options option {
			$$ = $1;

			assign_option($$, $1, $2, "persist", persist_time, 0);
			assign_option($$, $1, $2, "nopass",  nopass,       false);
			assign_option($$, $1, $2, "nolog",   nolog,        false);

			if ($$.persist_time != 0 && $$.nopass)
				yyerror("can not combine persist and nopass");
		} ;

persist:	TOK_PERSIST {
			$$.persist_time = 5 * 60;
		} | TOK_PERSIST '(' TOK_NUMBER ')' {
			bool succeed;
			bool const time_type_is_signed = ((time_t)-1 < (time_t)0);
			size_t const time_type_max = time_type_is_signed ? (time_t)((size_t)(time_t)-1 >> 1) : (time_t)-1;

			if (time_type_is_signed)
				$$.persist_time = safe_strtonum($3.str.buf, 0, time_type_max, &succeed);
			else
				$$.persist_time = safe_strtounum($3.str.buf, time_type_max, &succeed);

			if (!succeed)
				yyerror("too big persist time");

			if ($$.persist_time == 0)
				yyerror("persist time must be non-zero");

			free($3.str.buf);
		} ;
user:		TOK_NAME {
			$$.pw = safe_getpwnam($1.str.buf);

			if ($$.pw == NULL)
				parse_errors++;

			free($1.str.buf);
		} | TOK_NUMBER {
			bool succeed;
			uid_t uid = safe_strtounum($1.str.buf, UID_MAX, &succeed);

			if (!succeed || ($$.pw = safe_getpwuid(uid)) == NULL)
				parse_errors++;

			free($1.str.buf);
		} ;
group:		TOK_NAME {
			$$.gr = safe_getgrnam($1.str.buf);

			if ($$.gr == NULL)
				parse_errors++;

			free($1.str.buf);
		} | TOK_NUMBER {
			bool succeed;
			gid_t gid = safe_strtounum($1.str.buf, GID_MAX, &succeed);

			if (!succeed || ($$.gr = safe_getgrgid(gid)) == NULL)
				parse_errors++;

			free($1.str.buf);
		} ;
ident:		user {
			$$.ident.pw = $1.pw;
			$$.ident.gr = NULL;
		} | TOK_FROM group {
			$$.ident.pw = NULL;
			$$.ident.gr = $2.gr;
		} | user TOK_FROM group {
			$$.ident.pw = $1.pw;
			$$.ident.gr = $3.gr;
		} ;
target:	        TOK_AS user {
			$$.target.pw = $2.pw;
		} ;

argv:		execute {
			$$ = $1;
		} ;

execute:	/* Optional.  */ {
			$$.argc = 0;
			$$.argv = NULL;
		} | TOK_EXECUTE '{' strarray '}' {
			$$.argc = $3.listcount;
			$$.argv = (char const *const *const *)$3.strarray;
		} | TOK_EXECUTE '{' TOK_ELLIPSIS '}' {
			$$.argc = 1;
			$$.argv = NULL;
		} | TOK_EXECUTE '{' strarray TOK_ELLIPSIS '}' {
			$$.argc = $3.listcount + 1;
			$$.argv = (char const *const *const *)$3.strarray;
		} ;

strlist:	TOK_STRING {
			$$.strlist = xmalloc(2 * sizeof(char *));
			$$.strcount = 1;
			$$.strlist[0] = $1.str.buf;
			$$.strlist[1] = NULL;
		} | strlist ',' TOK_STRING {
			$$.strlist = xreallocarray($1.strlist, $$.strcount + 2, sizeof(char *));
			$$.strlist[$$.strcount++] = $3.str.buf;
			$$.strlist[$$.strcount] = NULL;
		} ;

strarray:	strlist {
			int i;

			$$.strarray = xmalloc(($1.strcount + 1) * sizeof(char **));
			$$.listcount = $1.strcount;

			for (i = 0; i < $$.strcount; i++) {
				$$.strarray[i] = xmalloc(2 * sizeof(char *));
				$$.strarray[i][0] = $1.strlist[i];
				$$.strarray[i][1] = NULL;
			}

			$$.strarray[i] = NULL;
			xfree($1.strlist);
		} | '[' strlist ']' {
			$$.strarray = xcalloc(2, sizeof(char **));
			$$.listcount = 1;
			$$.strarray[0] = $2.strlist;
			$$.strarray[1] = NULL;
		} | strarray ',' strarray {
			int i, j;

			$$.strarray = xreallocarray($1.strarray, $1.listcount + $3.listcount + 1, sizeof(char **));
			$$.listcount = $1.listcount + $3.listcount;

			for (i = $1.listcount, j = 0; i < $$.listcount; i++, j++)
				$$.strarray[i] = $3.strarray[j];

			$$.strarray[i] = NULL;
			xfree($3.strarray);
		} ;

%%

static void yyerror(char const *fmt, ...)
{
	va_list va;

	xfprintf(stderr, "%s: ", getprogname());

	va_start(va, fmt);
	xvfprintf(stderr, fmt, va);
	va_end(va);

	xfprintf(stderr, " at %u:%u\n", yylval.lineno + 1, yylval.colno + 1);

	parse_errors++;
}

void check_permissions(char const *filename)
{
	struct stat sb;

	if (stat(filename, &sb) != 0) {
		if (errno == ENOENT)
			err(EXIT_FAILURE, "doas is not enabled, %s required", filename);
		else
			err(EXIT_FAILURE, "stat(\"%s\")", filename);
	}

	if (sb.st_mode & (S_IWGRP | S_IWOTH))
		errx(EXIT_FAILURE, "%s is writable by group or other", filename);

	if (sb.st_uid != ROOT_UID || sb.st_gid != ROOT_UID)
		errx(EXIT_FAILURE, "%s is not owned by root", filename);
}

u_int parse_config(char const *filename)
{
	free_rules();
	memset(&yylval, '\0', sizeof(yylval));
	parse_errors = 0;
	yyin = fopen(filename, "r");

	if (yyin == NULL)
		err(EXIT_FAILURE, "could not open config file %s", filename);

	yyparse();
	fclose(yyin);

	return parse_errors;
}

#define free_and_nullify(p)	\
	do {			\
		xfree(p);	\
	} while (0)
#define free_vector_and_nullify(v)			\
	do {						\
		if (v != NULL) {			\
			size_t i;			\
			for (i = 0; v[i] != NULL; i++)	\
				xfree(v[i]);		\
			xfree(v);			\
		}					\
	} while (0)

void free_rules(void)
{
	size_t i;
	for (i = 0; i < nrules; i++) {
		int j;
		struct rule rule = rules[i];

		free_and_nullify(rule.ident.pw);
		free_and_nullify(rule.ident.gr);
		free_and_nullify(rule.target.pw);

		if (rule.argv != NULL) {
			for (j = 0; j < rule.argc; j++)
				free_vector_and_nullify(rule.argv[j]);

			free_and_nullify(rule.argv);
		}

		free_vector_and_nullify(rule.keepenvlist);
		free_vector_and_nullify(rule.setenvlist);
		free_vector_and_nullify(rule.unsetenvlist);
	}

	free_and_nullify(rules);
	maxrules = nrules = 0;
}

static void add_rule(struct rule const *r)
{
	if (nrules == maxrules) {
		maxrules = (maxrules == 0 ? 8 : maxrules * 2);
		rules = xreallocarray(rules, maxrules, 2 * sizeof(*rules));
	}

	memcpy(&rules[nrules++], r, sizeof(struct rule));
}

#if !HAVE_LEX && !HAVE_FLEX
struct keyword {
# if !HAVE_GPERF
	char const *const word;
# else
	int const word;
# endif
	size_t const length;
	int const token;
};

# if !HAVE_GPERF
static struct keyword const keywords[] = {
#  include "token-table.c"
};

/*
 * gnulib efa15594e17fc20827dba66414fb391e99905394
 *
 * CMP(a, b) performs a three-valued comparison on a vs. b.
 * It returns
 *   +1 if a > b
 *    0 if a == b
 *   -1 if a < b
 * The code  (a > b) - (a < b)  from Hacker's Delight para 2-9
 * avoids conditional jumps in all GCC versions >= 3.4.
 */
#  define CMP(n1, n2) (((n1) > (n2)) - ((n1) < (n2)))

/*
 * Return values:
 *   +1 if strcmp(p1, p2) > 0
 *    0 if strcmp(p1, p2) == 0
 *   -1 if strcmp(p1, p2) < 0
 */
static inline __nonnull((1, 2)) __const int fastmemcmp(void const *p1, void const *p2, size_t n)
{
	u_char const *s1 = (u_char const *)p1;
	u_char const *s2 = (u_char const *)p2;
	int comparison;

	if (n == 0)
		return 0;

	do {
		u_char c1 = *s1++;
		u_char c2 = *s2++;
		n--;
		comparison = CMP(c1, c2);
		if (comparison != 0)
			return comparison;
	} while (n != 0);

	return comparison;
}

static inline int get_token_by_word(char const *word, size_t length)
{
	size_t l = 0;
	size_t r = countof(keywords);

	while (l < r) {
		size_t m = l + (r - l) / 2;
		int d = CMP(length, keywords[m].length);

		switch (d != 0 ? d : fastmemcmp(word, keywords[m].word, length)) {
		case +1:
			l = m + 1;
			break;
		case 0:
			return keywords[m].token;
		case -1:
			r = m;
			break;
		}
	}

	yyerror("unknown keyword: %s", word);
	return TOK_UNKNOWN;
}
# else
#  include "get-keyword-by-word.c"

static inline int get_token_by_word(char const *word, size_t length)
{
	struct keyword const *kw = get_keyword_by_word(word, length);

	if (kw != NULL)
		return kw->token;

	yyerror("unknown keyword: %s", word);
	return TOK_UNKNOWN;
}
# endif

#include <ctype.h>

FILE *yyin = NULL;

static int yylex(void)
{
	char buf[256], *p = buf;
	u_int qpos = 0;
	bool quotes = false, escape = false;
	int c;
	enum { T_KEYWORD = 1, T_STRING, T_NUMBER, T_NAME } type = 0;

repeat:
	/* Skip whitespaces first.  */
	while (c = getc(yyin), isblank((unsigned char)c))
		yylval.colno++;

	/* Check for special one-character constructions.  */
	switch (c) {
	case '#':
		/* Skip comments.  NUL is allowed.  No continuation.  */
		while ((c = getc(yyin)) != '\n')
			if (c == EOF)
				goto eof;
		fallthrough;
	case '\n':
		yylval.colno = 0;
		yylval.lineno++;
		return '\n';
	case ',':
	case '(':
	case ')':
	case '[':
	case ']':
	case '{':
	case '}':
		return c;
	case EOF:
		goto eof;
	default:
		if (c == '"')
			type = T_STRING;
		else if (isdigit((unsigned char)c))
			type = T_NUMBER;
		else if (islower((unsigned char)c) || c == '.')
			type = T_KEYWORD;
		else if (c == '\'')
			type = T_NAME;
		else
			yyerror("unknown expression, expected string, number or keyword");
		break;
	}

	/* Parsing next word.  */
	for (;; c = getc(yyin), yylval.colno++) {
		switch (c) {
		case '\0':
			yyerror("unallowed character NUL (ignored)");
			escape = false;
			continue;
		case '\\':
			escape = !escape;
			if (escape)
				continue;
			break;
		case '\n':
			if (quotes)
				yyerror("unterminated quotes in column %u",
					qpos + 1);
			if (escape) {
				escape = false;
				yylval.colno = 0;
				yylval.lineno++;
				continue;
			}
			goto eow;
		case EOF:
			if (escape)
				yyerror("unterminated escape");
			if (quotes)
				yyerror("unterminated quotes in column %u",
					qpos);
			goto eow;
		case ',':
		case '(':
		case ')':
		case '[':
		case ']':
		case '{':
		case '}':
		case '#':
		case ' ':
		case '\t':
			if (!escape && !quotes)
				goto eow;
			break;
		case '"':
			if (!escape) {
				quotes = !quotes;
				if (quotes) {
					type = T_STRING;
					qpos = yylval.colno + 1;
				}
				continue;
			}
			break;
		case '\'':
			continue;
		}

		*p++ = c;
		if (p == endof(buf)) {
			yyerror("too long line");
			p = buf;
		}
		escape = false;
	}

eow:
	*p = '\0';
	ungetc(c == EOF ? '\n' : c, yyin);

	if (p == buf) {
		/*
		 * There could be a number of reasons for empty buffer,
		 * and we handle all of them here, to avoid cluttering
		 * the main loop.
		 */
		if (c == EOF) {
			goto eof;
		} else if (qpos == 0) {
			/*
			 * Accept, e.g., empty arguments:
			 *   execute "foo" ""
			 */
			goto repeat;
		}
	}

	switch (type) {
	case T_KEYWORD:
		return get_token_by_word(buf, p - buf);
	case T_STRING:
		yylval.str.buf = xstrdup(buf);
		return TOK_STRING;
	case T_NAME:
		yylval.str.buf = xstrdup(buf);
		return TOK_NAME;
	case T_NUMBER:
		yylval.str.buf = xstrdup(buf);
		return TOK_NUMBER;
	}

	yyerror("unknown token: %s", buf);
	return TOK_UNKNOWN;

eof:
	if (ferror(yyin) != 0)
		yyerror("input error reading config");

	return 0;
}
#endif
