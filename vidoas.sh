#!/bin/sh

# Copyright (c) 2020 Kimmo Suominen <kim@netbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# Edit a temporary copy of the doas.conf file and check it for syntax
# errors before installing it as the actual doas.conf file.

set -eu

PATH=/bin:/usr/bin:/usr/local/bin
export PATH

PROG="${0##*/}"

umask 022

DOAS_CONF=@DOAS_CONF@
doas_conf_mode="0600"

die()
{
    echo "${PROG}: ${@}" 1>&2
    exit 1
}

warn()
{
    echo "${PROG}: ${@}" 1>&2
}

get_intr()
{
    stty -a \
    | sed -En '
	/^(.* )?intr = / {
	    s///
	    s/;.*$//
	    p
	}
    '
}

owner_of()
{
    local file
    file="${1}"

    if stat --version >/dev/null 2>&1
    then
	stat -c '%U' "${file}"
    else
	stat -f '%Su' "${file}"
    fi \
    | awk '{print $1; exit}'
}

set_trap_rm()
{
    local file file_list
    file_list=
    for file
    do
	file_list="${file_list} '${file}'"
    done
    if [ -n "${file_list}" ]
    then
	trap "rm -f ${file_list}" 0 1 2 15
    fi
}

usage()
{
    cat <<EOF
Usage:	${PROG} [-n] [file]
	${PROG} -h

Edit a temporary copy of a doas configuration file and check it for
syntax errors before installing it as the actual configuration file.

When no file is named, ${PROG} will edit the default configuration file
for doas(1): @DOAS_CONF@

Options:
-h	Show this usage.
-n	Do not edit the file, just perform prerequisite checks. If this
	switch is repeated, all output will be suppressed and the check
	result is only indicated by the exit status.
EOF
}

noop=0

while getopts hn opt
do
    case "${opt}" in
    h) usage; exit 0;;
    n) noop=$((${noop} + 1));;
    *) usage 1>&2; exit 1;;
    esac
done
shift $((${OPTIND} - 1))

case ${#} in
0) ;;
1) DOAS_CONF="${1}";;
*) usage 1>&2; exit 1;;
esac

case ${noop} in
0) noop=false;;
1) noop=true;;
*) noop=true; exec >/dev/null 2>&1;;
esac

case "${DOAS_CONF}" in
-*)
    warn "Invalid filename: ${DOAS_CONF}"
    die  "Try using './${DOAS_CONF}' instead"
    ;;
esac

doas_conf_dir="$(dirname "${DOAS_CONF}")"
doas_conf_base="$(basename "${DOAS_CONF}")"
DOAS_CONF="${doas_conf_dir}/${doas_conf_base}"
doas_lock_file="${DOAS_CONF}.lck"

# These checks are only for producing nicer diagnostic messages to the
# user.  They are not relied on by the rest of the code.

if [ ! -e "${doas_conf_dir}" ]
then
    die "${doas_conf_dir} does not exist"
fi

if [ ! -d "${doas_conf_dir}" ]
then
    die "${doas_conf_dir} is not a directory"
fi

if [ ! -w "${doas_conf_dir}" ]
then
    owner="$(owner_of "${doas_conf_dir}")"
    warn "${doas_conf_dir} is not writable"
    die "You probably need to run ${PROG} as ${owner:-root}"
fi

tmp_doas="$(mktemp "${DOAS_CONF}.XXXXXXXXXX")" \
|| die "You probably need to run ${PROG} as root"
set_trap_rm "${tmp_doas}"

# It is important that the ln(1) command fails if the target already
# exists.  Some versions are known to behave like "ln -f" by default
# (removing any existing target).  Adjust PATH to avoid such ln(1)
# implementations.

tmp_test_ln="$(mktemp "${DOAS_CONF}.XXXXXXXXXX")"
set_trap_rm "${tmp_doas}" "${tmp_test_ln}"

if ln "${tmp_doas}" "${tmp_test_ln}" 2>/dev/null
then
    die 'ln(1) is not safe for creating lock files, bailing'
fi

# If a doas.conf file exists, copy it into the temporary file for
# editing.  If none exist, the editor will open with an empty file.

if [ -f "${DOAS_CONF}" ]
then
    if [ -r "${DOAS_CONF}" ]
    then
	cp "${DOAS_CONF}" "${tmp_doas}"
    else
	die "${DOAS_CONF} is not readable"
    fi
fi

if ${noop}
then
    if ! doas -C "${DOAS_CONF}"
    then
        die "${DOAS_CONF} contains syntax errors."
    fi
    warn 'OK: Prerequisite checks passed'
    exit 0
fi

# Link the temporary file to the lock file.

if ln "${tmp_doas}" "${doas_lock_file}"
then
    set_trap_rm "${tmp_doas}" "${tmp_test_ln}" "${doas_lock_file}"
else
    die "${DOAS_CONF} is already locked"
fi

# Some versions of vi(1) exit with a code that reflects the number of
# editing errors made.  This is why we ignore the exit code from the
# editor.

"${EDITOR:-vi}" "${tmp_doas}" || true

while ! doas -C "${tmp_doas}"
do
    warn "Press enter to edit doas.conf again to fix it,"
    warn "or interrupt ($(get_intr)) to cancel."
    read status
    "${EDITOR:-vi}" "${tmp_doas}" || true
done

# Use mv(1) to rename the temporary file to doas.conf as it is atomic.
# Update: No longer use mv as it messes up permissions on the doas.conf file.
# Use install with ownership set to root.

if [ -s "${tmp_doas}" ]
then
    if cmp -s "${tmp_doas}" "${DOAS_CONF}"
    then
	warn "No changes made"
	warn "${DOAS_CONF} unchanged"
    else
	install -o root -m "${doas_conf_mode}" \
	    "${tmp_doas}" "${DOAS_CONF}" \
	&& warn "${DOAS_CONF} updated"
    fi
else
    warn "Not installing an empty doas.conf file"
    warn "${DOAS_CONF} unchanged"
fi
