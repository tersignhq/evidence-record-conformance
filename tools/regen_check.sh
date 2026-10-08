#!/bin/sh
# Regenerate every vector profile from an EMPTY output directory and fail if any committed byte changes.
# POSIX sh + python3 stdlib only (runs inside slim containers). A generator that is missing fails the run.
set -eu
fail=0
aside=$(mktemp -d)  # a fresh directory per run, so a second run on one machine does not collide with the first
trap 'rm -rf "$aside"' EXIT  # the moved-aside copies are committed bytes; git holds them
check() {  # $1 = label, $2 = generator, $3 = output dir, $4 = manifest
    if [ ! -f "$2" ]; then echo "FAIL  $1: generator $2 is missing"; fail=1; return 0; fi
    before=$(sha256sum "$3"/*.json "$4" | sha256sum | cut -d' ' -f1)
    n=$(ls "$3"/*.json | wc -l)
    mv "$3" "$aside/$(echo "$3" | tr / _)"
    python3 "$2" > /dev/null
    after=$(sha256sum "$3"/*.json "$4" | sha256sum | cut -d' ' -f1)
    m=$(ls "$3"/*.json | wc -l)
    if [ "$before" = "$after" ] && [ "$n" = "$m" ]; then echo "ok    $1: $m vectors + manifest byte-identical"
    else echo "FAIL  $1: $n -> $m vectors, digest $before -> $after"; fail=1; fi
}
check structural tools/gen_vectors.py vectors MANIFEST.json
check crypto crypto/gen_crypto_vectors.py crypto/vectors crypto/MANIFEST.json
check eip712 crypto/gen_eip712_vectors.py crypto/eip712_vectors crypto/EIP712_MANIFEST.json
exit $fail
