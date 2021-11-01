
#ifndef _YYSTYPE_H
#define _YYSTYPE_H 1

#include "env.h"
#include "rule.h"

struct str {
	size_t siz;
	size_t len;
	char *buf;
};

struct yystype {
	union {
		RULE_ENTRY(union);
		struct {
			char const **strlist;
			int strcount;
		};
		struct {
			char const ***strarray;
			int listcount;
		};
		struct str str;
		struct passwd *pw;
		struct group *gr;
	};
	u_int lineno;
	u_int colno;
};

#define YYSTYPE struct yystype

extern YYSTYPE yylval;

#endif
