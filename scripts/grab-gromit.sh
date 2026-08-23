#!/usr/bin/env bash
#
# grab-gromit.sh -- mirror AOL "gromit" web apps (AIM Express, buddy-icon
# uploader, ...) out of the Wayback Machine.
#
# Everything lived under http://o.aolcdn.com/aim/gromit/<app>/<build>/, so one
# CDX prefix query per build enumerates the whole app. For each distinct URL we
# pick the capture closest to a target date, so you get a self-consistent
# snapshot rather than a mix of crawls years apart.
#
# Downloads are strictly SERIAL with a delay between every request. The Wayback
# Machine starts refusing connections outright (curl exit 7, not an HTTP 429)
# if you fan out, and it stays angry for a while -- so slow beats parallel.
#
# Needs only bash, curl, awk, shasum, od. No jq: we ask CDX for text output.
#
# Usage:
#   ./grab-gromit.sh                    # fetch every target below
#   ./grab-gromit.sh express            # just the named target(s)
#   ./grab-gromit.sh --list             # enumerate, download nothing
#   ./grab-gromit.sh --delay 5          # be extra polite
#   ./grab-gromit.sh -o clients express        # lands in clients/express/
#   ./grab-gromit.sh --url http://o.aolcdn.com/aim/gromit/x/y.swf --near 20130905

set -uo pipefail

CDX="https://web.archive.org/cdx/search/cdx"
WEB="https://web.archive.org/web"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

# --- what to mirror -------------------------------------------------------
# One entry per line: <name> <prefix> <near>
# near is YYYYMMDD, or "auto" to let the script choose (see auto.awk below).
TARGETS='
express       o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/  auto
express-html  o.aolcdn.com/aim/gromit/aim_express/gm/081202.1/             auto
iconuploader  o.aolcdn.com/aim/gromit/iconuploader/110128.1.5797/          auto
lifestream    o.aolcdn.com/lifestream/img/                                  auto
'

OUTDIR="archive"
DELAY=2.5
MAX_RETRIES=5
WINDOW_DAYS=180
LIST_ONLY=0
FORCE=0
NEAR_OVERRIDE="20130905"
MANIFEST_PATH=""
EXTRA_URLS=""
WANTED=""

REQUESTS=0
N_OK=0; N_SKIP=0; N_FAIL=0; N_SUSPECT=0

die() { echo "$*" >&2; exit 1; }
usage() { sed -n '3,22p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--outdir)      OUTDIR=$2; shift 2 ;;
        -d|--delay)       DELAY=$2; shift 2 ;;
        -r|--max-retries) MAX_RETRIES=$2; shift 2 ;;
        -w|--window-days) WINDOW_DAYS=$2; shift 2 ;;
        --near)           NEAR_OVERRIDE=$2; shift 2 ;;
        --manifest)       MANIFEST_PATH=$2; shift 2 ;;
        --url)            EXTRA_URLS="$EXTRA_URLS $2"; shift 2 ;;
        --list)           LIST_ONLY=1; shift ;;
        --force)          FORCE=1; shift ;;
        -h|--help)        usage ;;
        -*)               die "unknown option: $1" ;;
        *)                WANTED="$WANTED $1"; shift ;;
    esac
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/gromit.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$TMP"' EXIT
trap 'echo; echo "interrupted -- re-run to resume (existing files are skipped)"; exit 130' INT

# --- awk programs ---------------------------------------------------------
# In files rather than inline strings: awk's $1 and the shell's $1 don't mix.

cat > "$TMP/lib.awk" <<'AWKEOF'
# Days since the epoch from a YYYYMMDD... stamp (Howard Hinnant days_from_civil).
# Real day counts, so a capture on Dec 31 and one on Jan 1 come out 1 day apart
# rather than the ~8770 that naive subtraction of the stamps would give.
function d2n(s,   y,m,d,era,yoe,doy,doe) {
    y = substr(s,1,4)+0; m = substr(s,5,2)+0; d = substr(s,7,2)+0
    if (m < 1) m = 1
    if (d < 1) d = 1
    y -= (m <= 2)
    era = int((y >= 0 ? y : y-399) / 400)
    yoe = y - era*400
    doy = int((153*(m + (m > 2 ? -3 : 9)) + 2)/5) + d - 1
    doe = yoe*365 + int(yoe/4) - int(yoe/100) + doy
    return era*146097 + doe - 719468
}
# The archive keys o.aolcdn.com and o.aolcdn.com:80 as separate urlkeys, so
# without this every page shows up twice and each copy picks its own capture.
function norm(u,   rest,i,host,path) {
    rest = u
    sub(/^[a-zA-Z]+:\/\//, "", rest)
    i = index(rest, "/")
    if (i) { host = substr(rest,1,i-1); path = substr(rest,i) }
    else   { host = rest; path = "/" }
    sub(/:(80|443)$/, "", host)
    return tolower(host) path
}
AWKEOF

# Choose the capture date that pulls the tightest cluster out of the CDX rows.
# Every date present is tried as a candidate; the winner minimizes the total
# distance from each URL to its own nearest capture. This beats guessing,
# because a build's assets usually got swept up in one or two big crawls and we
# want to land on the biggest one.
cat > "$TMP/auto.awk" <<'AWKEOF'
{
    u = norm($1)
    if (!(u in cnt)) urls[++nu] = u
    day[u SUBSEP ++cnt[u]] = d2n($2)
    stamps[++ns] = $2
}
END {
    bestcost = -1
    for (i = 1; i <= ns; i++) {
        c = d2n(stamps[i]); cost = 0
        for (j = 1; j <= nu; j++) {
            u = urls[j]; m = -1
            for (x = 1; x <= cnt[u]; x++) {
                dd = day[u SUBSEP x] - c
                if (dd < 0) dd = -dd
                if (m < 0 || dd < m) m = dd
            }
            cost += m
        }
        if (bestcost < 0 || cost < bestcost) { bestcost = cost; best = stamps[i] }
    }
    print best
}
AWKEOF

# Collapse captures to one per normalized URL: the one nearest `near`.
cat > "$TMP/pick.awk" <<'AWKEOF'
BEGIN { target = d2n(near) }
{
    u = norm($1)
    off = d2n($2) - target
    if (off < 0) off = -off
    if (!(u in orig) || off < bestoff[u]) {
        bestoff[u] = off; orig[u] = $1; ts[u] = $2; mime[u] = $4
    }
}
END { for (u in orig) print orig[u], ts[u], mime[u], bestoff[u] }
AWKEOF

# --- fetching -------------------------------------------------------------
# fetch OUTFILE LABEL -- curl args come from the CURL_ARGS array, so callers can
# use -G/--data-urlencode for CDX and a plain URL for downloads.
fetch() {
    local out=$1 label=$2
    local attempt=0 code rc wait reason

    while :; do
        sleep "$DELAY"
        code=$(curl -sS -A "$UA" --max-time 120 -D "$TMP/hdr" \
                    -o "$out.part" -w '%{http_code}' "${CURL_ARGS[@]}" 2>"$TMP/err")
        rc=$?
        REQUESTS=$((REQUESTS+1))

        if [ "$rc" -eq 0 ] && [ "$code" = "200" ]; then
            mv "$out.part" "$out"
            return 0
        fi
        rm -f "$out.part"

        wait=""
        if [ "$rc" -ne 0 ]; then
            reason="curl exit $rc"
            # 7 = couldn't connect: we tripped the throttle. Back off hard and
            # keep the floor raised for the rest of the run.
            case "$rc" in
                7|28|56) bump_delay "connection refused/timed out" ;;
            esac
        else
            reason="HTTP $code"
            if [ "$code" = "404" ]; then
                echo "      !! 404 $label"
                return 1
            fi
            if [ "$code" = "429" ]; then
                bump_delay "rate limited"
                wait=$(awk 'tolower($1) ~ /^retry-after:/ {gsub(/\r/,""); print $2; exit}' "$TMP/hdr")
                case "$wait" in ''|*[!0-9]*) wait="" ;; esac
            fi
        fi

        if [ "$attempt" -ge "$MAX_RETRIES" ]; then
            echo "      !! $label: giving up after $((attempt+1)) attempts ($reason)"
            return 1
        fi
        [ -n "$wait" ] || wait=$(awk -v d="$DELAY" -v a="$attempt" \
            'BEGIN { v = d*(2^a)+2; print int(v > 120 ? 120 : v) }')
        attempt=$((attempt+1))
        echo "      $reason -- retry $attempt/$MAX_RETRIES in ${wait}s"
        sleep "$wait"
    done
}

bump_delay() {
    DELAY=$(awk -v d="$DELAY" 'BEGIN { v = d*1.5+1; printf "%.1f", (v > 30 ? 30 : v) }')
    echo "      $1 -- floor delay now ${DELAY}s"
}

# cdx_list PREFIX -> "original timestamp statuscode mimetype" rows on stdout
cdx_list() {
    CURL_ARGS=(-G "$CDX"
        --data-urlencode "url=$1"
        --data-urlencode "matchType=prefix"
        --data-urlencode "output=text"
        --data-urlencode "fl=original,timestamp,statuscode,mimetype"
        --data-urlencode "filter=statuscode:200"
        --data-urlencode "limit=5000")
    fetch "$TMP/cdx.txt" "cdx $1" || return 1
    awk 'NF >= 2' "$TMP/cdx.txt"
}

# --- local paths ----------------------------------------------------------
# Map an archived URL to a path under the target dir, preserving the tree. The
# build directory becomes the root, so .../gm/<build>/loadable/x.png lands at
# <outdir>/<name>/loadable/x.png. Query strings drop out of the filename but get
# hashed back in, because Main.html?env=prod and ?env=dev are different files.
local_path() {
    local original=$1 prefix=$2
    local rest path query stem ext tag root
    rest=${original#*://}
    case "$rest" in
        */*) path=/${rest#*/} ;;
        *)   path=/ ;;
    esac
    query=""
    case "$path" in *\?*) query=${path#*\?}; path=${path%%\?*} ;; esac
    root=/${prefix#*/}
    case "$path" in "$root"*) path=${path#"$root"} ;; esac
    path=${path#/}
    [ -n "$path" ] || path="index.html"
    case "$path" in */) path="${path}index.html" ;; esac
    if [ -n "$query" ]; then
        case "$path" in
            *.*) stem=${path%.*}; ext=.${path##*.} ;;
            *)   stem=$path; ext=.html ;;
        esac
        tag=$(printf '%s' "$query" | shasum | cut -c1-6)
        path="$stem.$tag$ext"
    fi
    printf '%s' "$path"
}

# True when we got the real bytes, false when the archive handed back its HTML
# wrapper -- the exact trap that yields an HTML file named OnlinePanel.swf.
magic_ok() {
    local f=$1 head4
    head4=$(od -A n -t x1 -N 4 "$f" 2>/dev/null | tr -d ' \n')
    case "$(printf '%s' "${f##*.}" | tr 'A-Z' 'a-z')" in
        swf)      case "$head4" in 465753*|435753*|5a5753*) return 0 ;; *) return 1 ;; esac ;;
        png)      case "$head4" in 89504e47*) return 0 ;; *) return 1 ;; esac ;;
        gif)      case "$head4" in 474946*) return 0 ;; *) return 1 ;; esac ;;
        jpg|jpeg) case "$head4" in ffd8ff*) return 0 ;; *) return 1 ;; esac ;;
        *)        return 0 ;;
    esac
}

# --- assemble the target list ---------------------------------------------
targets=$(printf '%s\n' "$TARGETS" | awk 'NF')
if [ -n "$(printf '%s' "$WANTED" | tr -d ' ')" ]; then
    sel=""
    for w in $WANTED; do
        line=$(printf '%s\n' "$targets" | awk -v n="$w" '$1 == n')
        [ -n "$line" ] || die "unknown target: $w (have: $(printf '%s\n' "$targets" | awk '{printf "%s ", $1}'))"
        sel="$sel$line
"
    done
    targets=$sel
fi
if [ -n "$(printf '%s' "$EXTRA_URLS" | tr -d ' ')" ]; then
    [ -n "$(printf '%s' "$WANTED" | tr -d ' ')" ] || targets=""
    for u in $EXTRA_URLS; do
        targets="$targets
adhoc ${u%%\?*} $NEAR_OVERRIDE"
    done
fi

# --- main loop ------------------------------------------------------------
# No pipe into the loop: a pipeline would run it in a subshell and the tallies
# and the raised DELAY floor would be discarded at the end of each target.
printf '%s\n' "$targets" | awk 'NF' > "$TMP/targets.txt"
: > "$TMP/manifest.json"
first=1

while read -r name prefix near; do
    printf '\n=== %s ===\n' "$name"
    printf '    prefix %s\n    near   %s\n' "$prefix" "$near"

    if ! cdx_list "$prefix" > "$TMP/rows.txt"; then
        echo "    !! CDX failed"
        N_FAIL=$((N_FAIL+1))
        continue
    fi
    if [ ! -s "$TMP/rows.txt" ]; then
        echo "    !! no captures found"
        continue
    fi

    if [ "$near" = "auto" ]; then
        near=$(awk -f "$TMP/lib.awk" -f "$TMP/auto.awk" "$TMP/rows.txt")
        echo "    auto-selected capture date $near"
    fi
    awk -v near="$near" -f "$TMP/lib.awk" -f "$TMP/pick.awk" "$TMP/rows.txt" \
        | sort > "$TMP/picks.txt"

    ncap=$(wc -l < "$TMP/rows.txt" | tr -d ' ')
    npick=$(wc -l < "$TMP/picks.txt" | tr -d ' ')
    echo "    $ncap captures -> $npick unique URLs"
    echo "    crawl dates: $(awk '{print substr($2,1,8)}' "$TMP/picks.txt" \
        | sort | uniq -c | sort -rn | awk '{printf "%s x%s, ", $2, $1}' | sed 's/, $//')"

    if [ "$LIST_ONLY" -eq 1 ]; then
        awk '{printf "      %s  %s  (%sd)  %s\n", $2, $3, $4, $1}' "$TMP/picks.txt"
        continue
    fi

    i=0
    while read -r original ts mime off; do
        i=$((i+1))
        rel="$name/$(local_path "$original" "$prefix")"
        dest="$OUTDIR/$rel"
        if [ "$FORCE" -eq 0 ] && [ -s "$dest" ]; then
            printf '[%3d/%s] skip  %s\n' "$i" "$npick" "$rel"
            N_SKIP=$((N_SKIP+1))
            continue
        fi
        note=""
        [ "$off" -gt "$WINDOW_DAYS" ] && note="  [${off}d off]"
        printf '[%3d/%s] get   %s%s\n' "$i" "$npick" "$rel" "$note"

        mkdir -p "$(dirname "$dest")"
        # id_ is what makes the archive return the ORIGINAL bytes instead of its
        # rewritten viewer page. Omit it and every .swf comes back as HTML.
        CURL_ARGS=("$WEB/${ts}id_/$original")
        if ! fetch "$dest" "$original"; then
            N_FAIL=$((N_FAIL+1))
            continue
        fi
        status=ok
        if magic_ok "$dest"; then
            N_OK=$((N_OK+1))
        else
            echo "      !! wrong magic bytes -- archive returned a wrapper?"
            status=suspect
            N_SUSPECT=$((N_SUSPECT+1))
        fi
        bytes=$(wc -c < "$dest" | tr -d ' ')
        echo "      $bytes bytes  $ts"
        [ "$first" -eq 1 ] || printf ',\n' >> "$TMP/manifest.json"
        first=0
        printf '  {"url": "%s", "timestamp": "%s", "mime": "%s", "path": "%s", "bytes": %s, "days_off": %s, "status": "%s"}' \
            "$original" "$ts" "$mime" "$rel" "$bytes" "$off" "$status" >> "$TMP/manifest.json"
    done < "$TMP/picks.txt"
done < "$TMP/targets.txt"

if [ "$LIST_ONLY" -eq 0 ]; then
    [ -n "$MANIFEST_PATH" ] || MANIFEST_PATH="$OUTDIR/manifest.json"
    mkdir -p "$(dirname "$MANIFEST_PATH")"
    { echo "["; cat "$TMP/manifest.json"; echo; echo "]"; } > "$MANIFEST_PATH"
    printf '\n%s ok, %s skipped, %s suspect, %s failed  (%s requests)\n' \
        "$N_OK" "$N_SKIP" "$N_SUSPECT" "$N_FAIL" "$REQUESTS"
    echo "manifest: $MANIFEST_PATH"
    [ "$N_SUSPECT" -gt 0 ] && echo "re-run with --force to retry the suspect files"
fi
exit 0
