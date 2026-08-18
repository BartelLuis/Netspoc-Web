#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

for path in \
    app/Application.js \
    htdocs/extjs4/ext-all.js \
    htdocs/silk-icons \
    resources \
    app.html; do
	if [ ! -e "$path" ]; then
		echo "Missing Docker build input: $path" >&2
		exit 1
	fi
done

if grep -q 'RUN mv app htdocs resources' Dockerfile; then
	echo "Dockerfile still contains the obsolete staging move" >&2
	exit 1
fi

echo "Docker build context is complete"
