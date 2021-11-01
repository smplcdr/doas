/* $OpenBSD: env.c,v 1.5 2016/09/15 00:58:23 deraadt Exp $ */
/*
 * Copyright (c) 2016 Ted Unangst <tedu@openbsd.org>
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

#include <sys/tree.h>
#include <sys/types.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "compat.h"
#include "env.h"
#include "rule.h"
#include "wrappers.h"

enum action {
	ACTION_INHERIT,
	ACTION_KEEP,
	ACTION_SET,
	ACTION_UNSET,
	ACTION_FORCE
};

struct envnode {
	RB_ENTRY(envnode) node;
	char const *name;
	char const *value;
	enum action action;
};

struct env {
	RB_HEAD(envtree, envnode) root;
	u_int count;
};

static inline char const *action_to_string(enum action action) __returns_nonnull;
static inline char const *action_to_string(enum action action)
{
	switch (action) {
	case ACTION_INHERIT:
		return "inherit";
	case ACTION_KEEP:
		return "keep";
	case ACTION_SET:
		return "set";
	case ACTION_UNSET:
		return "unset";
	case ACTION_FORCE:
		return "force";
	}

	err(EXIT_FAILURE, "unknown action");
}

static inline int envcmp(struct envnode const *restrict a,
			 struct envnode const *restrict b)
	__nonnull((1, 2)) __wur;
static inline int envcmp(struct envnode const *restrict a,
			 struct envnode const *restrict b)
{
	return strcmp(a->name, b->name);
}

#if defined(__DragonFly__)
RB_PROTOTYPE_STATIC(envtree, envnode, node, envcmp);
#endif
RB_GENERATE_STATIC(envtree, envnode, node, envcmp);

static inline void destroynode(struct envnode *node) __nonnull((1));
static inline void destroynode(struct envnode *node)
{
	xfree(node->name);
	xfree(node->value);
	xfree(node);
}

static inline struct envnode *createnode(char const *restrict name,
					 char const *restrict value,
					 enum action action)
	__returns_nonnull __nonnull((1)) __wur __malloc __dealloc(destroynode, 1);
static inline struct envnode *createnode(char const *restrict name,
					 char const *restrict value,
					 enum action action)
{
	struct envnode *node = xmalloc(sizeof(*node));

	node->name = xstrdup(name);
	node->value = value == NULL ? NULL : xstrdup(value);
	node->action = action;

	return node;
}

static inline struct envnode *insertnode(struct env *restrict env,
					 struct envnode *restrict node)
	__nonnull((1, 2));
static inline struct envnode *insertnode(struct env *restrict env,
					 struct envnode *restrict node)
{
	struct envnode *en = RB_INSERT(envtree, &env->root, node);

	if (en == NULL)
		env->count += (node->action != ACTION_UNSET);
	else
		errx(EXIT_FAILURE, "there is an element with the colliding key %s", node->name);

	return en;
}
static inline struct envnode *removenode(struct env *restrict env,
					 struct envnode *restrict node)
	__returns_nonnull __nonnull((1, 2));
static inline struct envnode *removenode(struct env *restrict env,
					 struct envnode *restrict node)
{
	struct envnode *en = RB_REMOVE(envtree, &env->root, node);

	if (en != NULL)
		env->count -= (node->action != ACTION_UNSET);
	else
		errx(EXIT_FAILURE, "there is no element with the given key %s", node->name);

	return en;
}

static inline int process_collision(struct env *const restrict env,
				    struct envnode *const restrict node,
				    char const *const restrict name,
				    enum action action)
	__nonnull((1, 2, 3));
static inline int process_collision(struct env *const restrict env,
				    struct envnode *const restrict node,
				    char const *const restrict name,
				    enum action action)
{
	if ((node->action == ACTION_FORCE && action != ACTION_INHERIT)
	 || (action == ACTION_FORCE && node->action != ACTION_INHERIT)) {
		warnx("%s: attempt to apply %s action to forced environ variable",
		      name, action_to_string(action == ACTION_FORCE ? node->action : action));
		return -1;
	}

	switch (node->action) {
	case ACTION_INHERIT:
		/* Inherited environs never repeat, so just remove previous entry.  */
		destroynode(removenode(env, node));
		break;
	case ACTION_KEEP:
	case ACTION_SET:
	case ACTION_UNSET:
		if (action != node->action)
			warnx("%s: attempt to do two different actions (%s and %s)",
			      name, action_to_string(node->action), action_to_string(action));
		else
			warnx("%s environ specified twice in %senv section", name, action_to_string(action));
		return -1;
	}

	return 0;
}

void defaultenv(struct env *const restrict env,
		struct passwd const *const restrict original,
		struct passwd const *const restrict target)
{
	struct envnode envlist[] = {
		{ .name = "DISPLAY",	.value = getenv("DISPLAY"),	.action = ACTION_INHERIT },
		{ .name = "TERM",	.value = getenv("TERM"),	.action = ACTION_INHERIT },
		{ .name = "HOME",	.value = target->pw_dir,	.action = ACTION_INHERIT },
		{ .name = "DOAS_USER",	.value = original->pw_name,	.action = ACTION_FORCE },
		{ .name = "LOGNAME",	.value = target->pw_name,	.action = ACTION_FORCE },
		{ .name = "PATH",	.value = GLOBAL_PATH,		.action = ACTION_FORCE },
		{ .name = "SHELL",	.value = target->pw_shell,	.action = ACTION_FORCE },
		{ .name = "USER",	.value = target->pw_name,	.action = ACTION_FORCE },
	};

	for (int i = 0; i < countof(envlist); i++) {
		if (envlist[i].value != NULL) {
			struct envnode *node;

			/* Process previous copies.  */
			if ((node = RB_FIND(envtree, &env->root, &envlist[i])) != NULL)
				process_collision(env, node,
						  envlist[i].name,
						  envlist[i].action);

			/* Assign value.  */
			insertnode(env, createnode(envlist[i].name,
						   envlist[i].value,
						   envlist[i].action));
		}
	}
}

void inheritenv(struct env *env)
{
	char const *const *envp;

	for (envp = (char const *const *)environ; *envp != NULL; envp++) {
		char const *e = *envp;
		char const *const eq = strchr(e, '=');
		struct envnode *node;
		struct envnode key = { .name = NULL, .value = NULL };

		key.name = xstrndup(e, eq - e);

		/* Process previous copies.  */
		/* If there is any environ with the same name, then yield.  */
		if ((node = RB_FIND(envtree, &env->root, &key)) == NULL) {
			key.value = eq + 1;

			/* At last, we have something to insert.  */
			insertnode(env, createnode(key.name, key.value, ACTION_INHERIT));
		}

		xfree(key.name);
	}
}

int keepenv(struct env *const restrict env,
	    char const *const restrict *const restrict envlist)
{
	char const *const restrict *envp;

	for (envp = envlist; *envp != NULL; envp++) {
		struct envnode *node;
		struct envnode key = { .name = *envp, .value = NULL };
		char const *eq = strchr(key.name, '=');

		if (eq != NULL) {
			key.name = xstrndup(key.name, eq - key.name);
			key.value = eq + 1;

			if (*key.value != '$') {
				warnx("$ character expected just after =");
				return -1;
			}

			key.value++;
		}

		/* Process previous copies.  */
		if ((node = RB_FIND(envtree, &env->root, &key)) != NULL)
			if (process_collision(env, node, key.name, ACTION_KEEP) != 0)
				return -1;

		/* Inherit from environ.  */
		key.value = getenv(key.value != NULL ? key.value : key.name);

		/* At last, we have something to insert.  */
		if (key.value != NULL)
			insertnode(env, createnode(key.name, key.value, ACTION_KEEP));
	}

	return 0;
}

int fillenv(struct env *restrict env,
	    char const *const restrict *const restrict envlist)
{
	char const *const restrict *envp;

	for (envp = envlist; *envp != NULL; envp++) {
		char const *const e = *envp;
		struct envnode *node, key = { .name = NULL, .value = NULL };

		/* Parse out environ name.  */
		char const *const eq = strchr(e, '=');

		if (eq == NULL) {
			warnc(EINVAL, "expected NAME=VALUE, but got: %s", e);
			return -1;
		}

		key.name = xstrndup(e, eq - e);

		/* Process previous copies.  */
		if ((node = RB_FIND(envtree, &env->root, &key)) != NULL)
		        if (process_collision(env, node, key.name, ACTION_SET) != 0)
				return -1;

		/* Assign value.  */
		insertnode(env, createnode(key.name, eq + 1, ACTION_SET));

		xfree(key.name);
	}

	return 0;
}

int unfillenv(struct env *restrict env,
	      char const *const restrict *const restrict envlist)
{
	char const *const restrict *envp;

	for (envp = envlist; *envp != NULL; envp++) {
		struct envnode *node;
		struct envnode key = { .name = *envp, .value = NULL };

		if (strchr(key.name, '=') != NULL) {
			warnc(EINVAL, "unexpected '=' character in environ name: %s", key.name);
			return -1;
		}

		if ((node = RB_FIND(envtree, &env->root, &key)) != NULL)
		        if (process_collision(env, node, key.name, ACTION_UNSET) != 0)
				return -1;

		insertnode(env, createnode(key.name, NULL, ACTION_UNSET));
	}

	return 0;
}

struct env *createenv(void)
{
	struct env *env = xmalloc(sizeof(*env));

	RB_INIT(&env->root);
	env->count = 0;

	return env;
}

static inline __malloc __returns_nonnull __nonnull((1)) __wur char **flattenenv(struct env *env)
{
	struct envnode *node, *next_node;
	u_int i = 0;
	char **envp = xreallocarray(NULL, env->count + 1, sizeof(char *));

	RB_FOREACH_SAFE(node, envtree, &env->root, next_node) {
		if (node->action != ACTION_UNSET) {
			size_t name_length = strlen(node->name);
			size_t value_length = strlen(node->value);
			char *e = xmalloc(name_length + 1 + value_length + 1);

			memcpy(e, node->name, name_length);
			e[name_length] = '=';
			memcpy(e + name_length + 1, node->value, value_length);
			e[name_length + value_length + 1] = '\0';

			envp[i++] = e;
		}

		destroynode(removenode(env, node));
	}

	xfree(env);

	envp[i] = NULL;

	return envp;
}

char **prepenv(struct env *const restrict env)
{
	return flattenenv(env);
}
