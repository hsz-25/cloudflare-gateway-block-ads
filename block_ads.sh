#!/bin/bash
# Home + Personal dual-source block script
set -uo pipefail

# Replace these variables with your actual Cloudflare API token and account ID
API_TOKEN="$API_TOKEN"
ACCOUNT_ID="$ACCOUNT_ID"
MAX_LIST_SIZE=1000
MAX_LISTS=100
MAX_RETRIES=10

# DNS Location IDs (Cloudflare Zero Trust > Networks > Resolvers & Proxies > DNS locations)
HOME_LOCATION_ID="3d4d56f8749d41ea97d291ec5faf3de7"
PERSONAL_LOCATION_ID="6b497a05ed454984b33cbf3554ca544b"

RUN_ID=$(date +%s)

# Define error function
function error() {
    echo "Error: $1"
    rm -f oisd_small_domainswild2.txt.new hagezi_light_onlydomains.txt.new
    rm -f *.chunk.* 2>/dev/null
    exit 1
}

# Small helper for authenticated Cloudflare API calls
function api() {
    local method="$1" path="$2" data="${3:-}"
    if [[ -n "$data" ]]; then
        curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X "$method" \
            "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}${path}" \
            -H "Authorization: Bearer ${API_TOKEN}" -H "Content-Type: application/json" --data "$data"
    else
        # Do not send a Content-Type header on requests with no body (e.g. GET/DELETE) -
        # Cloudflare's API returns 400 Bad Request if Content-Type: application/json is
        # present without a matching JSON body.
        curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X "$method" \
            "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}${path}" \
            -H "Authorization: Bearer ${API_TOKEN}"
    fi
}

# --- Download the latest domain lists ---

echo "Downloading OISD small..."
curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors "https://small.oisd.nl/domainswild2" | grep -vE '^\s*(#|$)' > oisd_small_domainswild2.txt.new || error "Failed to download the OISD list"
[[ -s oisd_small_domainswild2.txt.new ]] || error "The OISD list is empty"

echo "Downloading Hagezi Light..."
curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt" | grep -vE '^\s*(#|$)' > hagezi_light_onlydomains.txt.new || error "Failed to download the Hagezi list"
[[ -s hagezi_light_onlydomains.txt.new ]] || error "The Hagezi list is empty"

# --- Sanity check against the account-wide list cap before creating anything ---

oisd_lines=$(wc -l < oisd_small_domainswild2.txt.new)
hagezi_lines=$(wc -l < hagezi_light_onlydomains.txt.new)
oisd_lists_needed=$(( (oisd_lines + MAX_LIST_SIZE - 1) / MAX_LIST_SIZE ))
hagezi_lists_needed=$(( (hagezi_lines + MAX_LIST_SIZE - 1) / MAX_LIST_SIZE ))
total_needed=$(( oisd_lists_needed + hagezi_lists_needed ))

echo "OISD: ${oisd_lines} domains -> ${oisd_lists_needed} lists"
echo "Hagezi Light: ${hagezi_lines} domains -> ${hagezi_lists_needed} lists"
echo "Total lists needed: ${total_needed} (account limit: ${MAX_LISTS})"

(( total_needed <= MAX_LISTS )) || error "Combined lists needed (${total_needed}) exceeds the account limit of ${MAX_LISTS}. Aborting without making changes."

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

echo "Creating new OISD lists..."
read -ra oisd_ids <<< "$(create_lists_for_source "Block ads - OISD" "oisd_small_domainswild2.txt.new")"
echo "Created ${#oisd_ids[@]} OISD lists"

echo "Creating new Hagezi lists..."
read -ra hagezi_ids <<< "$(create_lists_for_source "Block ads - Hagezi" "hagezi_light_onlydomains.txt.new")"
echo "Created ${#hagezi_ids[@]} Hagezi lists"

# --- Build and upsert the two location-scoped block policies ---

# Home gets OISD only (comprehensive, low-breakage baseline for the whole household).
# Personal gets OISD + Hagezi Light (the more thorough combination) for Mac/iPhone/iPad.

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

upsert_policy "Block ads - Home" "$HOME_LOCATION_ID" "${oisd_ids[@]}"
upsert_policy "Block ads - Personal" "$PERSONAL_LOCATION_ID" "${oisd_ids[@]}" "${hagezi_ids[@]}"

# --- Clean up lists from the previous run, now that the policies point at the new ones ---

echo "Deleting superseded lists..."
old_ids=$(echo "$current_lists" | jq -r '.result[] | select((.name | startswith("Block ads - OISD")) or (.name | startswith("Block ads - Hagezi"))) | .id')
while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    echo "Deleting old list ${id}..."
    api DELETE "/gateway/lists/${id}" > /dev/null || echo "Warning: failed to delete list ${id}"
done <<< "$old_ids"

# --- Commit the updated source files back to the repo ---

mv oisd_small_domainswild2.txt.new oisd_small_domainswild2.txt
mv hagezi_light_onlydomains.txt.new hagezi_light_onlydomains.txt

git config --global user.email "${GITHUB_ACTOR_ID}+${GITHUB_ACTOR}@users.noreply.github.com"
git config --global user.name "$(gh api /users/${GITHUB_ACTOR} | jq .name -r)"
git add oisd_small_domainswild2.txt hagezi_light_onlydomains.txt
git diff --staged --quiet || git commit -m "Update domain lists"
git push origin main || echo "Nothing to push"
