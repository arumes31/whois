#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 <image-ref> <digest-directory> <image-repository> [alias-ref ...]" >&2
}

if (( $# < 3 )); then
  usage
  exit 2
fi

image_ref=$1
digest_dir=$2
image_repository=$3
shift 3

for command_name in docker jq sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Required command is unavailable: $command_name" >&2
    exit 1
  }
done

if [[ ! -d "$digest_dir" ]]; then
  echo "Digest directory does not exist: $digest_dir" >&2
  exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT

mapfile -t digest_files < <(find "$digest_dir" -maxdepth 1 -type f -printf '%f\n' | sort)
if (( ${#digest_files[@]} != 2 )); then
  echo "Expected exactly two scanned digest files, found ${#digest_files[@]}" >&2
  exit 1
fi

expected_platforms="$tmp_dir/expected-platforms"
expected_descriptors="$tmp_dir/expected-descriptors"
: > "$expected_descriptors"
printf '%s\n' linux/amd64 linux/arm64 > "$expected_platforms"

for file_name in "${digest_files[@]}"; do
  if [[ ! "$file_name" =~ ^linux-(amd64|arm64)-([[:xdigit:]]{64})$ ]]; then
    echo "Unexpected digest artifact name: $file_name" >&2
    exit 1
  fi

  platform="linux/${BASH_REMATCH[1]}"
  source_digest="sha256:${BASH_REMATCH[2],,}"
  source_raw="$tmp_dir/source-${BASH_REMATCH[1]}.json"
  docker buildx imagetools inspect "${image_repository}@${source_digest}" --raw > "$source_raw"

  mapfile -t platform_digests < <(
    jq -er --arg platform "$platform" '
      .manifests[]
      | select((.platform.os + "/" + .platform.architecture) == $platform)
      | .digest
    ' "$source_raw"
  )
  if (( ${#platform_digests[@]} != 1 )); then
    echo "Expected one $platform image in ${image_repository}@${source_digest}, found ${#platform_digests[@]}" >&2
    exit 1
  fi

  printf '%s\t%s\n' "$platform" "${platform_digests[0]}" >> "$expected_descriptors"
done

sort -u -o "$expected_descriptors" "$expected_descriptors"
cut -f1 "$expected_descriptors" > "$tmp_dir/source-platforms"
diff -u "$expected_platforms" "$tmp_dir/source-platforms"

final_raw="$tmp_dir/final-index.json"
docker buildx imagetools inspect "$image_ref" --raw > "$final_raw"

jq -er '
  .manifests[]
  | select(.platform.os == "linux")
  | [(.platform.os + "/" + .platform.architecture), .digest]
  | @tsv
' "$final_raw" | sort -u > "$tmp_dir/actual-descriptors"
diff -u "$expected_descriptors" "$tmp_dir/actual-descriptors"

while IFS=$'\t' read -r platform subject_digest; do
  mapfile -t attestation_digests < <(
    jq -er --arg subject "$subject_digest" '
      .manifests[]
      | select(
          .annotations["vnd.docker.reference.type"] == "attestation-manifest"
          and .annotations["vnd.docker.reference.digest"] == $subject
        )
      | .digest
    ' "$final_raw"
  )
  if (( ${#attestation_digests[@]} == 0 )); then
    echo "No attestation manifest references $platform image $subject_digest" >&2
    exit 1
  fi

  predicates="$tmp_dir/predicates-${platform//\//-}"
  : > "$predicates"
  for attestation_digest in "${attestation_digests[@]}"; do
    attestation_raw="$tmp_dir/attestation-${attestation_digest#sha256:}.json"
    docker buildx imagetools inspect "${image_repository}@${attestation_digest}" --raw > "$attestation_raw"
    jq -er '
      .layers[]?
      | select(.mediaType == "application/vnd.in-toto+json")
      | .annotations["in-toto.io/predicate-type"] // empty
    ' "$attestation_raw" >> "$predicates"
  done

  sort -u -o "$predicates" "$predicates"
  grep -Fxq 'https://spdx.dev/Document' "$predicates" || {
    echo "Missing SPDX SBOM attestation for $platform image $subject_digest" >&2
    exit 1
  }
  grep -Eq '^https://slsa\.dev/provenance/' "$predicates" || {
    echo "Missing SLSA provenance attestation for $platform image $subject_digest" >&2
    exit 1
  }
done < "$expected_descriptors"

final_digest="sha256:$(sha256sum "$final_raw" | cut -d' ' -f1)"
for alias_ref in "$@"; do
  alias_raw="$tmp_dir/alias-$(printf '%s' "$alias_ref" | sha256sum | cut -d' ' -f1).json"
  docker buildx imagetools inspect "$alias_ref" --raw > "$alias_raw"
  alias_digest="sha256:$(sha256sum "$alias_raw" | cut -d' ' -f1)"
  if [[ "$alias_digest" != "$final_digest" ]]; then
    echo "$alias_ref resolved to $alias_digest, expected $final_digest" >&2
    exit 1
  fi
done

echo "Verified $image_ref at $final_digest with linux/amd64 and linux/arm64 SPDX/SLSA attestations"
