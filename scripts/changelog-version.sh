#!/usr/bin/env bash
#
# Reads CHANGELOG.md (Keep a Changelog format) so CI and the release workflow
# agree on what the next release is.
#
# Usage:
#   scripts/changelog-version.sh version        Print the newest released version
#                                               (the first "## [X.Y.Z] - YYYY-MM-DD"
#                                               heading; "[Unreleased]" is skipped).
#   scripts/changelog-version.sh notes X.Y.Z    Print the body of that version's
#                                               section, for the release notes.
#   scripts/changelog-version.sh check          Exit non-zero unless the newest
#                                               version is well formed, dated,
#                                               has a link reference, and is not
#                                               behind the highest v* tag.
#
# The file is CHANGELOG.md in the current directory unless CHANGELOG_FILE is set.

set -euo pipefail

CHANGELOG_FILE="${CHANGELOG_FILE:-CHANGELOG.md}"
SEMVER='[0-9]+\.[0-9]+\.[0-9]+'
HEADING="^## \[($SEMVER)\] - ([0-9]{4}-[0-9]{2}-[0-9]{2})$"

die() {
    echo "changelog-version: $*" >&2
    exit 1
}

[ -f "$CHANGELOG_FILE" ] || die "$CHANGELOG_FILE not found"

# First released heading. Lines are read one at a time so the regex is
# anchored to a whole line, which a grep -o could not guarantee.
top_heading() {
    local line
    while IFS= read -r line; do
        if [[ "$line" =~ $HEADING ]]; then
            printf '%s\n%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
            return 0
        fi
    done < "$CHANGELOG_FILE"
    return 1
}

cmd_version() {
    local parsed
    parsed=$(top_heading) || die "no '## [X.Y.Z] - YYYY-MM-DD' heading in $CHANGELOG_FILE"
    sed -n '1p' <<< "$parsed"
}

cmd_notes() {
    local want="${1:-}"
    [ -n "$want" ] || die "notes needs a version argument"
    [[ "$want" =~ ^$SEMVER$ ]] || die "notes: '$want' is not X.Y.Z"
    local found=0 line
    while IFS= read -r line; do
        if [ "$found" -eq 0 ]; then
            if [[ "$line" =~ $HEADING ]] && [ "${BASH_REMATCH[1]}" = "$want" ]; then
                found=1
            fi
            continue
        fi
        # The next "## " heading or the link-reference block ends the section.
        if [[ "$line" == "## "* ]] || [[ "$line" =~ ^\[[^]]+\]:\ https?:// ]]; then
            break
        fi
        printf '%s\n' "$line"
    done < "$CHANGELOG_FILE"
    [ "$found" -eq 1 ] || die "notes: no section for $want"
}

# Compare two X.Y.Z strings. Prints -1, 0 or 1.
semver_cmp() {
    local IFS=.
    local -a a=($1) b=($2)
    local i
    for i in 0 1 2; do
        if ((10#${a[$i]} < 10#${b[$i]})); then echo -1; return; fi
        if ((10#${a[$i]} > 10#${b[$i]})); then echo 1; return; fi
    done
    echo 0
}

highest_tag() {
    git tag -l 'v[0-9]*' 2>/dev/null \
        | sed -E -n "s/^v($SEMVER)$/\1/p" \
        | sort -t. -k1,1n -k2,2n -k3,3n \
        | tail -1
}

cmd_check() {
    local parsed version date
    parsed=$(top_heading) || die "no '## [X.Y.Z] - YYYY-MM-DD' heading in $CHANGELOG_FILE"
    version=$(sed -n '1p' <<< "$parsed")
    date=$(sed -n '2p' <<< "$parsed")

    # The date must be a real calendar date. date(1) differs between BSD and
    # GNU, so try both forms.
    if ! { date -j -f '%Y-%m-%d' "$date" '+%Y-%m-%d' 2>/dev/null \
            || date -d "$date" '+%Y-%m-%d' 2>/dev/null; } | grep -qx "$date"; then
        die "[$version] has an invalid date '$date'"
    fi

    grep -qE "^\[$version\]: https?://" "$CHANGELOG_FILE" \
        || die "[$version] has no '[$version]: <url>' link reference"

    local tag
    tag=$(highest_tag)
    if [ -n "$tag" ] && [ "$(semver_cmp "$version" "$tag")" -lt 0 ]; then
        die "newest changelog version $version is behind tag v$tag"
    fi

    if [ -n "$tag" ] && [ "$(semver_cmp "$version" "$tag")" -eq 0 ]; then
        echo "changelog: $version is released (tag v$tag exists)"
    else
        echo "changelog: $version is pending release${tag:+ (latest tag v$tag)}"
    fi
}

case "${1:-}" in
    version) cmd_version ;;
    notes)   cmd_notes "${2:-}" ;;
    check)   cmd_check ;;
    *)       die "usage: $0 version | notes X.Y.Z | check" ;;
esac
