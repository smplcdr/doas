{
	if (HAVE_GPERF == 1)
		printf "%s, %u, %s\n", $1, length($1), $2
	else
		printf "{ \"%s\", %u, %s },\n", $1, length($1), $2
}
