#!/usr/bin/env bash
#
# Reports outdated dependencies and offers to upgrade them.
#
#   Go modules   Direct requirements in go.mod with a newer release in the
#                same major version, plus any that are deprecated or whose
#                current version is retracted. Indirect modules are counted
#                only: they follow along when go mod tidy runs.
#   Tool pins    golangci-lint and govulncheck as pinned in the CI workflow,
#                and the Go release line CI builds with. Report only, as the
#                pins live in workflow files this script never edits.
#
# Releases younger than COOLDOWN_DAYS (default 7, matching dependabot.yml)
# are flagged "too fresh" and left out of "all", but can still be picked.
#
# On a terminal it then asks: [a]ll, [p]ick or [N]one. An upgrade runs
# go get, go mod tidy, go build and go test, then shows the go.mod diff.
# Nothing is committed. Without a terminal it prints the report and exits.
#
# Usage: scripts/outdated.sh    (or: make outdated)

set -euo pipefail

COOLDOWN_DAYS="${COOLDOWN_DAYS:-7}"
CI_FILE="${CI_FILE:-.github/workflows/ci.yml}"

if ! [[ "$COOLDOWN_DAYS" =~ ^[0-9]+$ ]]; then
    echo "outdated: COOLDOWN_DAYS must be a whole number of days" >&2
    exit 1
fi

if [ -t 1 ]; then
    BOLD=$'\033[1m' DIM=$'\033[2m' RED=$'\033[31m' GREEN=$'\033[32m'
    YELLOW=$'\033[33m' CYAN=$'\033[36m' NC=$'\033[0m'
else
    BOLD='' DIM='' RED='' GREEN='' YELLOW='' CYAN='' NC=''
fi

for bin in go jq; do
    command -v "$bin" > /dev/null || { echo "outdated: $bin is not installed" >&2; exit 1; }
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

header() { printf '\n%s%s%s\n' "$BOLD" "$1" "$NC"; }

# jq filter: whole days since an RFC 3339 time, or -1 when there is none.
# Fractional seconds are stripped because fromdateiso8601 rejects them.
AGE='if . then ((now - (sub("\\.[0-9]+"; "") | fromdateiso8601)) / 86400 | floor) else -1 end'

# Prints the age column, marking releases inside the cooldown.
age_label() {
    local days=$1
    if [ "$days" -lt 0 ]; then
        printf '%s' "age unknown"
    elif [ "$days" -lt "$COOLDOWN_DAYS" ]; then
        printf '%s%dd, too fresh%s' "$YELLOW" "$days" "$NC"
    else
        printf '%dd' "$days"
    fi
}

# ---------------------------------------------------------------- Go modules

echo "Checking Go modules against the module proxy..."
if ! go list -m -u -json all > "$tmp/all.json" 2> "$tmp/all.err"; then
    echo "${RED}outdated: go list failed:${NC}" >&2
    cat "$tmp/all.err" >&2
    exit 1
fi

# Direct modules with an update: path, current, latest, age in days.
jq -r "
    select(.Main != true and (.Indirect | not) and .Update)
    | [.Path, .Version, .Update.Version, (.Update.Time | $AGE)] | @tsv
" "$tmp/all.json" > "$tmp/direct.tsv"

# Direct modules that are deprecated or sit on a retracted version, one line
# per warning (read collapses empty tab-separated fields, so none are emitted).
jq -r '
    select(.Main != true and (.Indirect | not))
    | (if .Deprecated then [.Path, .Version, "deprecated: " + .Deprecated] else empty end),
      (if .Retracted then [.Path, .Version, "retracted: " + (.Retracted | join("; "))] else empty end)
    | @tsv
' "$tmp/all.json" > "$tmp/warn.tsv"

indirect_count=$(jq -s '[.[] | select(.Main != true and .Indirect and .Update)] | length' "$tmp/all.json")

header "Go modules (direct)"
if [ -s "$tmp/direct.tsv" ]; then
    printf '  %s%-40s %-14s %-14s %s%s\n' "$DIM" "MODULE" "CURRENT" "LATEST" "AGE" "$NC"
    while IFS=$'\t' read -r path cur latest days; do
        printf '  %-40s %-14s %s%-14s%s %s\n' \
            "$path" "$cur" "$GREEN" "$latest" "$NC" "$(age_label "$days")"
    done < "$tmp/direct.tsv"
else
    echo "  ${GREEN}All direct modules are up to date.${NC}"
fi

if [ -s "$tmp/warn.tsv" ]; then
    echo
    while IFS=$'\t' read -r path cur msg; do
        printf '  %s!%s %s %s: %s\n' "$RED" "$NC" "$path" "$cur" "$msg"
    done < "$tmp/warn.tsv"
fi

if [ "$indirect_count" -gt 0 ]; then
    printf '\n  %s%d indirect module(s) also have updates; go mod tidy moves those along.%s\n' \
        "$DIM" "$indirect_count" "$NC"
fi

# ---------------------------------------------------------------- Tool pins

# Prints "<version> <age-days>" for a module's latest release, or nothing.
latest_of() {
    go list -m -json "$1@latest" 2> /dev/null | jq -r "[.Version, (.Time | $AGE)] | @tsv" 2> /dev/null || true
}

# Prints one tool line: name, pinned version, where it is pinned, latest.
tool_line() {
    local name=$1 pinned=$2 where=$3 latest=$4 days=$5
    if [ -z "$pinned" ]; then
        printf '  %-14s %spin not found in %s%s\n' "$name" "$YELLOW" "$CI_FILE" "$NC"
    elif [ -z "$latest" ]; then
        printf '  %-14s %-10s %slatest version lookup failed%s\n' "$name" "$pinned" "$YELLOW" "$NC"
    elif [ "$pinned" = "$latest" ]; then
        printf '  %-14s %-10s %sup to date%s\n' "$name" "$pinned" "$GREEN" "$NC"
    else
        printf '  %-14s %-10s -> %s%-10s%s %s\n' "$name" "$pinned" \
            "$GREEN" "$latest" "$NC" "$(age_label "$days")"
        printf '  %-14s %spinned in %s%s\n' "" "$CYAN" "$where" "$NC"
    fi
}

header "Tool pins (report only)"
if [ ! -f "$CI_FILE" ]; then
    echo "  ${YELLOW}$CI_FILE not found, skipping.${NC}"
else
    # golangci-lint: the first "version:" input after the action's "uses:" line.
    lint_ref=$(awk '/golangci-lint-action@/ { found = 1 }
        found && /^[[:space:]]*version:/ { print NR ":" $2; exit }' "$CI_FILE")
    lint_pin=${lint_ref#*:}
    IFS=$'\t' read -r lint_latest lint_days <<< "$(latest_of github.com/golangci/golangci-lint/v2)" || true
    tool_line golangci-lint "$lint_pin" "$CI_FILE:${lint_ref%%:*}" "${lint_latest:-}" "${lint_days:--1}"

    vuln_ref=$(grep -n -o 'govulncheck@v[0-9][0-9.]*' "$CI_FILE" | head -n 1 || true)
    vuln_pin=${vuln_ref##*@}
    IFS=$'\t' read -r vuln_latest vuln_days <<< "$(latest_of golang.org/x/vuln)" || true
    vuln_where="$CI_FILE:${vuln_ref%%:*}"
    grep -q 'govulncheck@' scripts/pre-ci-check.sh 2> /dev/null && vuln_where="$vuln_where, scripts/pre-ci-check.sh"
    tool_line govulncheck "$vuln_pin" "$vuln_where" "${vuln_latest:-}" "${vuln_days:--1}"

    # Go: CI pins a release line ("1.26.x"); compare major.minor with the latest.
    go_line=$(grep -o "go-version:[[:space:]]*'[0-9.x]*'" "$CI_FILE" | head -n 1 | grep -o "[0-9][0-9.x]*" || true)
    go_latest=$(go list -m -f '{{.Version}}' go@latest 2> /dev/null || true)
    go_directive=$(awk '$1 == "go" { print $2; exit }' go.mod)
    if [ -z "$go_line" ] || [ -z "$go_latest" ]; then
        printf '  %-14s %scould not compare (CI line "%s", latest "%s")%s\n' "Go" "$YELLOW" "$go_line" "$go_latest" "$NC"
    elif [ "${go_line%.x}" = "$(cut -d. -f1-2 <<< "$go_latest")" ]; then
        printf '  %-14s %-10s %sup to date (latest %s)%s\n' "Go" "$go_line" "$GREEN" "$go_latest" "$NC"
    else
        printf '  %-14s %-10s -> %s%-10s%s newer release line\n' \
            "Go" "$go_line" "$GREEN" "$go_latest" "$NC"
        printf '  %-14s %spinned as go-version in .github/workflows/*.yml%s\n' "" "$CYAN" "$NC"
        printf '  %-14s %sgo.mod says go %s, the minimum supported version; raise it deliberately.%s\n' \
            "" "$DIM" "$go_directive" "$NC"
    fi
fi

# ---------------------------------------------------------------- Upgrade

echo
if [ ! -s "$tmp/direct.tsv" ]; then
    exit 0
fi

if [ ! -t 0 ] || [ ! -t 1 ]; then
    echo "Not on a terminal, so not offering upgrades."
    exit 0
fi

if git rev-parse --is-inside-work-tree > /dev/null 2>&1 \
    && ! { git diff --quiet -- go.mod go.sum && git diff --cached --quiet -- go.mod go.sum; }; then
    echo "${YELLOW}go.mod or go.sum has uncommitted changes. Commit or stash them first, so the"
    echo "upgrade diff is only the upgrade.${NC}"
    exit 0
fi

eligible=$(awk -F'\t' -v c="$COOLDOWN_DAYS" '$4 >= c' "$tmp/direct.tsv" | wc -l | tr -d ' ')
read -r -p "Upgrade? [a]ll ($eligible past the cooldown), [p]ick, [N]one: " choice || choice=""

: > "$tmp/chosen"
case "$choice" in
    a | A)
        awk -F'\t' -v c="$COOLDOWN_DAYS" '$4 >= c { print $1 "@" $3 }' "$tmp/direct.tsv" > "$tmp/chosen"
        ;;
    p | P)
        # Read answers from the terminal: stdin of this loop is the module list.
        while IFS=$'\t' read -r path cur latest days; do
            note=""
            [ "$days" -lt "$COOLDOWN_DAYS" ] && note=" ${YELLOW}($(age_label "$days"))${NC}"
            read -r -p "  $path $cur -> $latest$note? [y/N] " yn < /dev/tty || yn=""
            case "$yn" in y | Y) echo "$path@$latest" >> "$tmp/chosen" ;; esac
        done < "$tmp/direct.tsv"
        ;;
esac

if [ ! -s "$tmp/chosen" ]; then
    echo "Nothing upgraded."
    exit 0
fi

# Runs one step, and on failure says how to back out and stops.
step() {
    printf '%s==>%s %s\n' "$CYAN" "$NC" "$*"
    if ! "$@"; then
        echo "${RED}Failed: $*${NC}"
        echo "The changes are left in place. To back out: git checkout -- go.mod go.sum"
        exit 1
    fi
}

modules=()
while IFS= read -r m; do modules+=("$m"); done < "$tmp/chosen"

step go get "${modules[@]}"
step go mod tidy
step go build ./...
step go test ./...

header "go.mod changes"
git --no-pager diff --stat -- go.mod go.sum
git --no-pager diff -- go.mod
echo
echo "${GREEN}Upgraded ${#modules[@]} module(s). Build and tests pass. Nothing has been committed.${NC}"
