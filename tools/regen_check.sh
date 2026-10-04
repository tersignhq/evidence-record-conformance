#!/bin/sh
# Regenerate every vector profile from an EMPTY output directory and fail if any committed byte changes.
# POSIX sh + python3 stdlib only (runs inside slim containers). A generator that is absent on this checkout is skipped and named.
set -eu
fail=0
check() {  # $1 = label, $2 = generator, $3 = output dir, $4 = manifest
    if [ ! -f "$2" ]; then echo "skip  $1 ($2 not on this checkout)"; return 0; fi
    before=$(sha256sum "$3"/*.json "$4" | sha256sum | cut -d' ' -f1)
    n=$(ls "$3"/*.json | wc -l)
    mkdir -p /tmp/regen_aside && mv "$3" "/tmp/regen_aside/$(echo "$3" | tr / _)"
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
