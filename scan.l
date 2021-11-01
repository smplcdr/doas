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

/* scan.l: the (f)lex description file for the scanner.  */

%{

#include "wrappers.h"

/* Here the order of includes is important since some
   yacc implementations defines YYSTYPE
   as int if it is not declarated before
   y.tab.h, thus include yystype.h before
   yacc header.  */
#include "yystype.h" /* Get YYSTYPE definition.  */
#include "y.tab.h" /* Get TOK_* and (may be) yylval prototype.  */

/* Using flex, we can ask for a smaller input buffer.
   With lex, this does nothing! */
#undef YY_READ_BUF_SIZE
#undef YY_BUF_SIZE
#define YY_READ_BUF_SIZE 256
#define YY_BUF_SIZE 256

#define YY_USER_ACTION					\
	do {						\
		/* The only pattern with new line	\
		   is the first pattern, where new line	\
		   character only in the end.  */	\
		if (yytext[yyleng - 1] == '\n') {	\
			yylval.lineno++;		\
			yylval.colno = 0;		\
		} else {				\
			yylval.colno += yyleng;		\
		}					\
	} while (0);

static void append_character(struct str *s, char c);
static void append_string(struct str *str, const char *string, size_t length);

%}

%x STRING

%%

(#[^\n]*)?\n {
	return '\n';
}

"..." {
	return TOK_ELLIPSIS;
}
"as" {
	return TOK_AS;
}
"deny" {
	return TOK_DENY;
}
"execute" {
	return TOK_EXECUTE;
}
"from" {
	return TOK_FROM;
}
"inheritenv" {
	return TOK_INHERITENV;
}
"keepenv" {
	return TOK_KEEPENV;
}
"nolog" {
	return TOK_NOLOG;
}
"nopass" {
	return TOK_NOPASS;
}
"permit" {
	return TOK_PERMIT;
}
"persist" {
	return TOK_PERSIST;
}
"setenv" {
	return TOK_SETENV;
}
"unsetenv" {
	return TOK_UNSETENV;
}

","|":"|"("|")"|"["|"]"|"{"|"}" {
  return yytext[0];
}

[ \t]+ {
	/* Ignore spaces and tabs.  */ ;
}

\'[a-z_][a-z0-9_\-]{0,30}[a-z0-9_\-\$]?\' {
	yylval.str.siz = yyleng - 1;
	yylval.str.len = yyleng - 2;
	yylval.str.buf = xmalloc(yylval.str.siz);
	memcpy(yylval.str.buf, yytext + 1, yylval.str.len);
	yylval.str.buf[yylval.str.len] = '\0';
	return TOK_NAME;
}

\'[^\']*\' {
	warnx("wrong user name: %s", yytext);
	return TOK_UNKNOWN;
}

\" {
	yylval.str.siz = 16;
	yylval.str.len = 0;
	yylval.str.buf = xmalloc(16 * sizeof(char));
	yylval.str.buf[0] = '\0';
	BEGIN(STRING);
}

<STRING>\\\" {
	append_character(&yylval.str, '"');
}
<STRING>\n {
	warnx("new line is not allowed in string");
	return TOK_UNKNOWN;
}
<STRING>\0 {
	warnx("nul character is not allowed in string");
	return TOK_UNKNOWN;
}
<STRING>[^\"\n\0]+ {
	append_string(&yylval.str, yytext, yyleng);
}
<STRING>\" {
	yylval.str.siz = yylval.str.len + 1;
	yylval.str.buf = xrealloc(yylval.str.buf, yylval.str.siz);
	BEGIN(INITIAL);
	return TOK_STRING;
}

[0-9]+ {
	char *src, *dst;

	/* Remove leading zeros.  */
	src = dst = yytext;

	while (*src == '0')
		src++;
	if (*src == '\0')
		src--;

	yyleng -= (src - yytext);

	memmove(dst, src, yyleng);
	dst[yyleng] = '\0';

	yylval.str.siz = yyleng + 1;
	yylval.str.len = yyleng;
	yylval.str.buf = xmemdup(yytext, yyleng + 1);

	return TOK_NUMBER;
}

[[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC][\x80-\xBF][\x80-\xBF]|\xED[\x80-\x9F][\x80-\xBF]|[\xEE\xEF][\x80-\xBF][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF][\x80-\xBF]|[\xF1-\xF3][\x80-\xBF][\x80-\xBF][\x80-\xBF]|\xF4[\x80-\x8F][\x80-\xBF][\x80-\xBF]]+ {
	/* https://stackoverflow.com/questions/921648/how-to-make-a-flex-lexical-scanner-to-read-utf-8-characters-input#comment73101581_921648 */
	/* Do not parse anything else, just say that we do not know
	   what to do with this input.  */
	warnx("unknown token %s", yytext);
	return TOK_UNKNOWN;
}

%%

static void append_character(struct str *str, char character)
{
	if (str->len + 1 >= str->siz)
		str->buf = xrealloc(str->buf, ++str->siz);

	str->buf[str->len++] = character;
	str->buf[str->len] = '\0';
}

static void append_string(struct str *str, const char *string, size_t length)
{
	if (str->len + length >= str->siz)
		str->buf = xrealloc(str->buf, str->siz *= 2);

	memcpy(str->buf + str->len, string, length);
	str->len += length;
	str->buf[str->len] = '\0';
}
