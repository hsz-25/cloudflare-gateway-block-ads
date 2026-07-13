#!/usr/bin/env python3
"""
Home + Personal Cloudflare Gateway blocklist sync.

Sources:
  - Hagezi Normal      (ads, affiliate, tracking, metrics, telemetry, phishing, malware...)
  - Hagezi Pro "delta" (only the domains in Hagezi Pro that are NOT already in Hagezi
                         Normal - Pro is a superset of Normal, so we avoid paying for the
                         same domain twice across two sets of Lists)

Sharing:
  - The Hagezi Normal lists are shared by BOTH the Home and Personal policies.
  - The Hagezi Pro delta lists are used ONLY by the Personal policy, making Personal
    effectively equivalent to full Hagezi Pro, without duplicating the domains Normal
    and Pro share.

Update strategy (this is the important part):
  Cloudflare's free-tier account is capped at ~300 Gateway Lists. Home+Personal together
  need on the order of 150-200 lists just for one "generation" of Normal+Delta, so there
  is NOT enough headroom to build a whole second generation of lists next to the old one
  and swap atomically (this is what silently broke every previous version of this script -
  it kept hitting Cloudflare's error 2017 "Maximum number of lists reached" mid-run).

  Instead of delete-everything-then-recreate (which works, but blocks NO ads for the
  minutes it takes to rebuild - a real outage every single run) or
  create-everything-then-delete-old (which needs 2x list capacity - doesn't fit here),
  this script does an in-place diff/PATCH sync, same approach used by
  github.com/SeriousHoax/Cloudflare-Gateway-Adblock-Updater:

    1. Fetch the domains currently sitting in "our" lists (by name prefix).
    2. Diff against the freshly downloaded blocklist -> domains to add, domains to remove.
    3. PATCH existing lists in place (append/remove) instead of recreating them.
    4. Only create brand new lists for whatever doesn't fit in existing ones.
    5. Repoint the Home/Personal policies at the current full set of list IDs.
    6. Only THEN delete any list that ended up empty, plus any list from a fully
       retired naming scheme (old OISD / Hagezi-Light lists from earlier iterations
       of this project) - safe now that nothing references them anymore.

  Net effect: no gap in ad-blocking coverage during a routine run, and no need to ever
  hold two generations of lists in the account at once.

  A small state file (state.json, committed back to the repo) hashes the last-synced
  source files so unchanged blocklists skip all Cloudflare API calls entirely.
"""
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

API_TOKEN = os.environ["API_TOKEN"]
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"

CHUNK_SIZE = 1000          # domains per Cloudflare list
PATCH_BATCH = 1000         # domains per single PATCH append/remove call
MAX_LISTS = 300            # empirically-verified enforced cap on this account

HOME_LOCATION_ID = "3d4d56f8749d41ea97d291ec5faf3de7"
PERSONAL_LOCATION_ID = "6b497a05ed454984b33cbf3554ca544b"

HAGEZI_NORMAL_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt"
HAGEZI_PRO_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt"

NORMAL_PREFIX = "Block ads - Hagezi Normal"
DELTA_PREFIX = "Block ads - Hagezi ProDelta"
# Fully retired naming schemes from earlier iterations of this project - these are no
# longer referenced by any policy once Personal is repointed, and get deleted outright.
RETIRED_PREFIXES = ("Block ads - OISD",)

STATE_FILE = "state.json"


def log(msg):
    print(msg, flush=True)


def die(msg):
    print(f"Error: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def api(method, path, data=None, retries=6, fatal=True):
    url = f"{BASE_URL}{path}"
    body = json.dumps(data).encode() if data is not None else None
    last_err = None
    for attempt in range(retries):
        req = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {API_TOKEN}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            resp_body = e.read().decode(errors="replace")
            if e.code == 429 or e.code >= 500:
                last_err = f"HTTP {e.code}: {resp_body}"
                time.sleep(min(2 ** attempt, 30))
                continue
            last_err = f"HTTP {e.code}: {resp_body}"
            if fatal:
                die(f"API call failed: {method} {path} -> HTTP {e.code}\nResponse: {resp_body}")
            return None
        except Exception as e:  # network errors, timeouts, etc.
            last_err = str(e)
            time.sleep(min(2 ** attempt, 30))
    if fatal:
        die(f"API call failed after {retries} attempts: {method} {path} ({last_err})")
    log(f"Warning: non-fatal API call failed after {retries} attempts: {method} {path} ({last_err})")
    return None


def paginate(path, per_page=500):
    results = []
    page = 1
    while True:
        sep = "&" if "?" in path else "?"
        resp = api("GET", f"{path}{sep}per_page={per_page}&page={page}")
        batch = resp["result"]
        results.extend(batch)
        # Cloudflare's result_info exposes total_count, not total_pages - stop once a
        # page comes back short (fewer than per_page items means it was the last page).
        if len(batch) < per_page:
            break
        page += 1
    return results


def chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def download_domains(url):
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        text = resp.read().decode()
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.add(line)
    return domains


def sha256_of(domains):
    h = hashlib.sha256()
    for d in sorted(domains):
        h.update(d.encode())
        h.update(b"\n")
    return h.hexdigest()


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")


def sync_list_set(prefix, target_domains, existing_lists, budget):
    """
    Diff/PATCH an existing set of Cloudflare Lists (identified by name prefix) so their
    combined contents equal target_domains, creating new lists only for the overflow
    that doesn't fit in existing ones.

    existing_lists: [{"id":..., "name":...}, ...] already filtered to this prefix.
    budget: how many brand new lists we're still allowed to create this run (global cap).

    Returns (final_list_ids, empty_list_ids, lists_created, budget_remaining).
    """
    current_map = {}  # list_id -> set(domains currently in that list)
    for lst in existing_lists:
        items = paginate(f"/gateway/lists/{lst['id']}/items")
        current_map[lst["id"]] = {i["value"] for i in items}

    all_current = set()
    for domains in current_map.values():
        all_current |= domains

    to_add = list(target_domains - all_current)
    to_remove = all_current - target_domains

    log(f"[{prefix}] existing lists: {len(existing_lists)}, current domains: {len(all_current)}, "
        f"target domains: {len(target_domains)}, to add: {len(to_add)}, to remove: {len(to_remove)}")

    # Remove domains that shouldn't be there anymore
    for lst in existing_lists:
        lid = lst["id"]
        remove_here = list(current_map[lid] & to_remove)
        for batch in chunks(remove_here, PATCH_BATCH):
            # Cloudflare's Patch List endpoint takes `remove` as plain value strings,
            # but `append` as full {"value": ...} item objects - these are NOT symmetric.
            api("PATCH", f"/gateway/lists/{lid}", {"remove": batch})
        if remove_here:
            current_map[lid] -= set(remove_here)

    # Fill freed-up space (and part of the new domains) into existing lists first
    add_queue = list(to_add)
    for lst in existing_lists:
        lid = lst["id"]
        space = CHUNK_SIZE - len(current_map[lid])
        if space > 0 and add_queue:
            take = add_queue[:space]
            add_queue = add_queue[space:]
            for batch in chunks(take, PATCH_BATCH):
                api("PATCH", f"/gateway/lists/{lid}", {"append": [{"value": d} for d in batch]})
            current_map[lid] |= set(take)

    # Whatever's left needs brand new lists
    final_ids = [lst["id"] for lst in existing_lists]
    lists_created = 0
    next_n = len(existing_lists) + 1
    new_lists_needed = (len(add_queue) + CHUNK_SIZE - 1) // CHUNK_SIZE
    if new_lists_needed > budget:
        die(f"[{prefix}] needs {new_lists_needed} new lists but only {budget} remain within the "
            f"{MAX_LISTS}-list account cap. Aborting before creating anything for this source.")

    for batch in chunks(add_queue, CHUNK_SIZE):
        name = f"{prefix} - {next_n:03d}"
        resp = api("POST", "/gateway/lists", {
            "name": name,
            "type": "DOMAIN",
            "items": [{"value": d} for d in batch],
        })
        lid = resp["result"]["id"]
        final_ids.append(lid)
        current_map[lid] = set(batch)
        next_n += 1
        lists_created += 1
        budget -= 1

    empty_ids = [lid for lid in final_ids if len(current_map.get(lid, set())) == 0]
    kept_ids = [lid for lid in final_ids if lid not in empty_ids]

    log(f"[{prefix}] final list count: {len(kept_ids)} ({lists_created} newly created, "
        f"{len(empty_ids)} now empty and will be dropped)")

    return kept_ids, empty_ids, lists_created, budget


def build_traffic(location_id, list_ids):
    clauses = " or ".join(f"any(dns.domains[*] in ${lid})" for lid in list_ids)
    return f'dns.location in {{"{location_id}"}} and ({clauses})'


def upsert_policy(name, location_id, list_ids, current_policies):
    traffic = build_traffic(location_id, list_ids)
    existing = next((r for r in current_policies if r["name"] == name), None)
    payload = {
        "name": name,
        "traffic": traffic,
        "action": "block",
        "enabled": True,
        "filters": ["dns"],
        "rule_settings": {"block_page_enabled": False, "block_reason": ""},
    }
    if existing is None:
        log(f"Creating policy {name}...")
        api("POST", "/gateway/rules", payload)
    else:
        log(f"Updating policy {name} ({existing['id']})...")
        api("PUT", f"/gateway/rules/{existing['id']}", payload)


def git(*args):
    subprocess.run(["git", *args], check=True)


def main():
    log("Downloading Hagezi Normal + Pro...")
    normal_domains = download_domains(HAGEZI_NORMAL_URL)
    pro_domains = download_domains(HAGEZI_PRO_URL)
    if not normal_domains:
        die("Hagezi Normal download is empty")
    if not pro_domains:
        die("Hagezi Pro download is empty")

    delta_domains = pro_domains - normal_domains
    if not delta_domains:
        die("Hagezi Pro delta is empty - something is wrong upstream")

    log(f"Hagezi Normal: {len(normal_domains)} domains")
    log(f"Hagezi Pro delta (Pro minus Normal): {len(delta_domains)} domains")

    state = load_state()
    normal_hash = sha256_of(normal_domains)
    delta_hash = sha256_of(delta_domains)
    if state.get("normal_sha256") == normal_hash and state.get("delta_sha256") == delta_hash:
        log("No change in either source since the last successful sync. Nothing to do.")
        return

    log("Fetching current Gateway policies...")
    current_policies = api("GET", "/gateway/rules")["result"]

    log("Fetching current Gateway lists...")
    current_lists = paginate("/gateway/lists")

    normal_lists = sorted(
        (l for l in current_lists if l["name"].startswith(NORMAL_PREFIX)),
        key=lambda l: l["name"],
    )
    delta_lists = sorted(
        (l for l in current_lists if l["name"].startswith(DELTA_PREFIX)),
        key=lambda l: l["name"],
    )
    retired_lists = [
        l for l in current_lists
        if any(l["name"].startswith(p) for p in RETIRED_PREFIXES)
    ]

    # Budget: total room left under the account cap for brand-new lists this run,
    # ignoring lists we're about to retire (they'll be freed up by the time we're done,
    # but we don't rely on that - the diff/patch approach barely creates new lists anyway).
    already_used = len(current_lists)
    budget = MAX_LISTS - already_used
    if budget < 0:
        budget = 0
    log(f"Account currently has {already_used} lists; {budget} of new headroom before the "
        f"{MAX_LISTS} cap (retired lists will free up {len(retired_lists)} more once dropped).")

    normal_ids, normal_empty, normal_created, budget = sync_list_set(
        NORMAL_PREFIX, normal_domains, normal_lists, budget)
    delta_ids, delta_empty, delta_created, budget = sync_list_set(
        DELTA_PREFIX, delta_domains, delta_lists, budget)

    upsert_policy("Block ads - Home", HOME_LOCATION_ID, normal_ids, current_policies)
    upsert_policy("Block ads - Personal", PERSONAL_LOCATION_ID, normal_ids + delta_ids, current_policies)

    # Only now that no policy references them anymore: drop empty lists + retired lists.
    to_delete = normal_empty + delta_empty + [l["id"] for l in retired_lists]
    log(f"Deleting {len(to_delete)} superseded/empty lists...")
    for lid in to_delete:
        api("DELETE", f"/gateway/lists/{lid}", fatal=False)

    save_state({"normal_sha256": normal_hash, "delta_sha256": delta_hash})

    actor = os.environ.get("GITHUB_ACTOR", "github-actions")
    actor_id = os.environ.get("GITHUB_ACTOR_ID", "41898282")
    git("config", "--global", "user.email", f"{actor_id}+{actor}@users.noreply.github.com")
    git("config", "--global", "user.name", actor)
    git("add", STATE_FILE)
    result = subprocess.run(["git", "diff", "--staged", "--quiet"])
    if result.returncode != 0:
        git("commit", "-m", "Update sync state")
        subprocess.run(["git", "push", "origin", "main"])
    else:
        log("Nothing to commit.")

    log("Done.")


if __name__ == "__main__":
    main()
