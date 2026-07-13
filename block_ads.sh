#!/bin/bash
# Home + Personal dual-source block script
#
# Sources:
#   - Hagezi Normal       (ads, affiliate, tracking, metrics, telemetry, phishing, malware...)
#   - Hagezi Pro "delta"  (only the domains in Hagezi Pro that are NOT already in Hagezi
#                          Normal - Pro is a superset of Normal, so we avoid paying for the
#                          same domain twice across two Lists)
#
# Sharing:
#   - The Hagezi Normal lists are created ONCE and referenced by BOTH the Home and Personal
#     policies (Cloudflare Lists can be referenced by multiple rules).
#   - The Hagezi Pro delta lists are referenced ONLY by the Personal policy, making Personal
#     effectively equivalent to full Hagezi Pro, without ever creating duplicate lists for the
#     domains Normal and Pro share.
set -uo pipefail

# Replace these variables with your actual Cloudflare API token and account ID
API_TOKEN="$API_TOKEN"
ACCOUNT_ID="$ACCOUNT_ID"
MAX_LIST_SIZE=1000
MAX_LISTS=300
MAX_RETRIES=10

# DNS Location IDs (Cloudflare Zero Trust > Networks > Resolvers & Proxies > DNS locations)
HOME_LOCATION_ID="3d4d56f8749d41ea97d291ec5faf3de7"
PERSONAL_LOCATION_ID="6b497a05ed454984b33cbf3554ca544b"

RUN_ID=$(date +%s)

# Define error function
function error() {
    echo "Error: $1"
    rm -f hagezi_normal.txt.new hagezi_pro.txt.new hagezi_pro_delta.txt.new
    rm -f *.sorted *.chunk.* 2>/dev/null
    exit 1
}

# Small helper for authenticated Cloudflare API calls
function api() {
    local method="$1" path="$2" data="${3:-}"
    local url="https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}${path}"
    local response http_code body

    if [[ -n "$data" ]]; then
        response=$(curl -sSL --retry "$MAX_RETRIES" --retry-all-errors -X "$method" "$url" \
            -H "Authorization: Bearer ${API_TOKEN}" -H "Content-Type: application/json" \
            --data "$data" -w $'\n%{http_code}')
    else
        response=$(curl -sSL --retry "$MAX_RETRIES" --retry-all-errors -X "$method" "$url" \
            -H "Authorization: Bearer ${API_TOKEN}" -w $'\n%{http_code}')
    fi

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
        echo "API call failed: ${method} ${path} -> HTTP ${http_code}" >&2
        echo "Response body: ${body}" >&2
        return 1
    fi

    echo "$body"
}

# --- Download the latest domain lists ---

echo "Downloading Hagezi Normal..."
curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt" | grep -vE '^\s*(#|$)' > hagezi_normal.txt.new || error "Failed to download the Hagezi Normal list"
[[ -s hagezi_normal.txt.new ]] || error "The Hagezi Normal list is empty"

echo "Downloading Hagezi Pro..."
curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt" | grep -vE '^\s*(#|$)' > hagezi_pro.txt.new || error "Failed to download the Hagezi Pro list"
[[ -s hagezi_pro.txt.new ]] || error "The Hagezi Pro list is empty"

# --- Compute the Pro "delta": domains in Pro that are not already in Normal ---
# Hagezi's tiers are cumulative (Pro is a superset of Normal), so we only need the
# incremental domains to get full Pro coverage without duplicating list slots.

echo "Computing Hagezi Pro delta (Pro minus Normal)..."
sort -u hagezi_normal.txt.new -o hagezi_normal.txt.sorted
sort -u hagezi_pro.txt.new -o hagezi_pro.txt.sorted
comm -23 hagezi_pro.txt.sorted hagezi_normal.txt.sorted > hagezi_pro_delta.txt.new
[[ -s hagezi_pro_delta.txt.new ]] || error "The Hagezi Pro delta is empty - something is wrong upstream"

# --- Sanity check against the account-wide list cap before creating anything ---

normal_lines=$(wc -l < hagezi_normal.txt.new)
delta_lines=$(wc -l < hagezi_pro_delta.txt.new)
normal_lists_needed=$(( (normal_lines + MAX_LIST_SIZE - 1) / MAX_LIST_SIZE ))
delta_lists_needed=$(( (delta_lines + MAX_LIST_SIZE - 1) / MAX_LIST_SIZE ))
total_needed=$(( normal_lists_needed + delta_lists_needed ))

echo "Hagezi Normal: ${normal_lines} domains -> ${normal_lists_needed} lists (shared by Home + Personal)"
echo "Hagezi Pro delta: ${delta_lines} domains -> ${delta_lists_needed} lists (Personal only)"
echo "Total distinct lists needed: ${total_needed} (working limit: ${MAX_LISTS})"

(( total_needed <= MAX_LISTS )) || error "Combined lists needed (${total_needed}) exceeds the working limit of ${MAX_LISTS}. Aborting without making changes."

# --- Fetch current state ---

echo "Fetching current policies..."
current_policies=$(api GET "/gateway/rules") || error "Failed to fetch current policies"

echo "Fetching current lists..."
current_lists=$(api GET "/gateway/lists") || error "Failed to fetch current lists"

# Creates fresh Cloudflare Lists for a domain file, named with a unique run suffix
# so they never collide with lists from a previous run. Prints the created list
# IDs (space separated) to stdout; progress goes to stderr.
function create_lists_for_source() {
    local prefix="$1" file="$2"
    split -l "$MAX_LIST_SIZE" "$file" "${file}.chunk."
    local ids=()
    local n=1
    for chunk in "${file}.chunk."*; do
        local items name payload resp id
        items=$(jq -R -s 'split("\n") | map(select(length>0) | { "value": . })' "$chunk")
        name=$(printf "%s %s - %03d" "$prefix" "$RUN_ID" "$n")
        payload=$(jq -n --arg n "$name" --argjson items "$items" '{"name":$n,"type":"DOMAIN","items":$items}')
        resp=$(api POST "/gateway/lists" "$payload") || error "Failed creating list ${name}"
        id=$(echo "$resp" | jq -r '.result.id // empty')
        [[ -n "$id" ]] || error "No id returned when creating list ${name}: ${resp}"
        echo "Created list ${name} (${id})" >&2
        ids+=("$id")
        n=$((n+1))
        rm -f "$chunk"
    done
    echo "${ids[@]}"
}

echo "Creating new Hagezi Normal lists..."
read -ra normal_ids <<< "$(create_lists_for_source "Block ads - Hagezi Normal" "hagezi_normal.txt.new")"
echo "Created ${#normal_ids[@]} Hagezi Normal lists"

echo "Creating new Hagezi Pro delta lists..."
read -ra delta_ids <<< "$(create_lists_for_source "Block ads - Hagezi ProDelta" "hagezi_pro_delta.txt.new")"
echo "Created ${#delta_ids[@]} Hagezi Pro delta lists"

# --- Build and upsert the two location-scoped block policies ---

# Home:     Hagezi Normal
# Personal: Hagezi Normal + Hagezi Pro delta (== effectively full Hagezi Pro, dedup'd)

function build_traffic() {
    local location_id="$1"; shift
    local clauses=()
    for id in "$@"; do
        clauses+=("any(dns.domains[*] in \$${id})")
    done
    local joined
    joined=$(printf ' or %s' "${clauses[@]}")
    joined=${joined:4}
    echo "dns.location in {\"${location_id}\"} and (${joined})"
}

function upsert_policy() {
    local name="$1" location_id="$2"; shift 2
    local traffic policy_id payload
    traffic=$(build_traffic "$location_id" "$@")
    policy_id=$(echo "$current_policies" | jq -r --arg N "$name" '.result[] | select(.name==$N) | .id // empty')
    payload=$(jq -n --arg name "$name" --arg traffic "$traffic" '{
        name: $name,
        traffic: $traffic,
        action: "block",
        enabled: true,
        filters: ["dns"],
        rule_settings: {
            block_page_enabled: false,
            block_reason: ""
        }
    }')
    if [[ -z "$policy_id" ]]; then
        echo "Creating policy ${name}..."
        api POST "/gateway/rules" "$payload" > /dev/null || error "Failed creating policy ${name}"
    else
        echo "Updating policy ${name} (${policy_id})..."
        api PUT "/gateway/rules/${policy_id}" "$payload" > /dev/null || error "Failed updating policy ${name}"
    fi
}

upsert_policy "Block ads - Home" "$HOME_LOCATION_ID" "${normal_ids[@]}"
upsert_policy "Block ads - Personal" "$PERSONAL_LOCATION_ID" "${normal_ids[@]}" "${delta_ids[@]}"

# --- Clean up lists from the previous run, now that the policies point at the new ones ---

echo "Deleting superseded lists..."
old_ids=$(echo "$current_lists" | jq -r '.result[] | select((.name | startswith("Block ads - OISD")) or (.name | startswith("Block ads - Hagezi"))) | .id')
while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    echo "Deleting old list ${id}..."
    api DELETE "/gateway/lists/${id}" > /dev/null || echo "Warning: failed to delete list ${id}"
done <<< "$old_ids"

# --- Commit the updated source files back to the repo ---

mv hagezi_normal.txt.new hagezi_normal.txt
mv hagezi_pro_delta.txt.new hagezi_pro_delta.txt
rm -f hagezi_pro.txt.new *.sorted

git config --global user.email "${GITHUB_ACTOR_ID}+${GITHUB_ACTOR}@users.noreply.github.com"
git config --global user.name "$(gh api /users/${GITHUB_ACTOR} | jq .name -r)"
git add hagezi_normal.txt hagezi_pro_delta.txt
git diff --staged --quiet || git commit -m "Update domain lists"
git push origin main || echo "Nothing to push"
