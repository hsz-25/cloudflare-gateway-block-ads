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

Capacity safety valve:
  If Normal+Delta ever approaches Cloudflare's real 300,000-domain / 300-list cap, this
  script automatically and permanently switches the Personal policy's second source from
  full Hagezi Pro to the smaller, curated Hagezi Pro Mini list (still layered on top of
  Normal), so the account never runs out of room without anyone having to intervene. See
  CAPACITY_DOWNGRADE_THRESHOLD below.

Scheduling:
  The workflow's cron is aimed at ~5 AM Central (two UTC entries bracket the DST
  transition), but GitHub Actions schedule triggers are best-effort and can fire
  significantly late under load - observed in practice firing over 5 hours after
  the configured time. An earlier version of this script enforced a strict "only
  do real work if it's actually 5:00-5:29 AM Central right now" window and
  skipped everything otherwise; that made the sync silently no-op on any day
  GitHub delayed the trigger past the window, which defeats the entire point of
  having a nightly sync. There is no time-of-day gate anymore: every scheduled
  trigger does real work, whenever it actually fires. Two cron entries still
  exist so there are two chances per day for GitHub to actually run it near the
  intended time, but neither is ever skipped for being "too late."
"""
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

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
HAGEZI_PRO_MINI_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.mini-onlydomains.txt"

NORMAL_PREFIX = "Block ads - Hagezi Normal"
DELTA_PREFIX = "Block ads - Hagezi ProDelta"
WHITELIST_PREFIX = "Allow - Whitelist"

STATE_FILE = "state.json"

# Real cap is 300 lists x 1,000 entries = 300,000. Once a prospective sync would put
# Normal+Delta+Whitelist combined at or above this, permanently switch Personal's second
# source from full Hagezi Pro (~234k domains, ~83k of them not already in Normal) to
# Hagezi Pro Mini (~72k domains, ~35k not already in Normal) - same *kind* of coverage
# (ads/trackers/malware/phishing), just a smaller curated set. Switching drops the
# combined total from ~244k to ~200k in one run, so even a threshold this close to the
# real cap lands safely once triggered - it's a big one-time drop, not a slow approach to
# the wall. One-way switch by design: no automatic switching back, so behavior never
# flaps night to night.
CAPACITY_DOWNGRADE_THRESHOLD = 299_000


def is_retired(name):
    """
    True for lists from fully-retired naming schemes used by earlier iterations of this
    project (plain OISD lists, and bare "Block ads - Hagezi <timestamp> - NNN" lists from
    the original Hagezi-Light run, which predate the Normal/ProDelta split). These are
    never referenced once Personal is repointed at the current Normal+Delta list IDs, so
    they're safe to delete outright rather than diff/patch.
    """
    if name.startswith("Block ads - OISD"):
        return True
    if name.startswith(NORMAL_PREFIX) or name.startswith(DELTA_PREFIX):
        return False
    if name.startswith("Block ads - Hagezi "):
        return True
    return False


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
                parsed = json.loads(resp.read())
            # Cloudflare sometimes returns HTTP 200 with a logical failure in the body
            # (e.g. rate limiting, transient validation errors) - "result" is null in
            # that case, which would otherwise blow up callers that expect a list/dict.
            if isinstance(parsed, dict) and parsed.get("success") is False:
                last_err = f"HTTP 200 but success=false: {json.dumps(parsed.get('errors'))}"
                time.sleep(min(2 ** attempt, 30))
                continue
            return parsed
        except urllib.error.HTTPError as e:
            resp_body = e.read().decode(errors="replace")
            if e.code == 429 or e.code >= 500:
                last_err = f"HTTP {e.code}: {resp_body}"
                time.sleep(min(2 ** attempt, 30))
                continue
            last_err = f"HTTP {e.code}: {resp_body}"
            if fatal:
                die(f"API call failed: {method} {path} -> HTTP {e.code}\nResponse: {resp_body}")
            log(f"Warning: non-fatal API call failed: {method} {path} -> HTTP {e.code}: {resp_body}")
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
        batch = (resp or {}).get("result")
        if batch is None:
            # A well-formed 2xx response with a null/missing "result" (e.g. the resource
            # was deleted between listing it and fetching it, or a transient API quirk) -
            # treat as "nothing more here" rather than crashing the whole run.
            log(f"Warning: {path} page {page} returned no result body, treating as empty/last page")
            break
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
        time.sleep(0.05)  # light throttle - avoid bursting hundreds of GETs at once

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


# Security Threats category blocking is a SEPARATE Gateway rule ("Security Threats
# Block (Home + Personal)"), managed by hand in the Cloudflare dashboard via its
# category checkbox UI - deliberately NOT touched by this script. Keeping it out of
# the ad-block traffic expression means it can be edited without ever hand-editing
# wirefilter, and this script can never accidentally clobber it.
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


def resolve_pro_source(state, whitelist_count):
    """
    Decides which Hagezi Pro variant feeds the Personal policy's delta this run, and
    whether that decision needs to change (the capacity safety valve). Returns
    (pro_domains, pro_label, mode, downgraded_this_run).
    """
    previous_mode = state.get("blocklist_mode", "full_pro")

    if previous_mode == "pro_mini":
        # Already downgraded in an earlier run - one-way switch, stay on Mini.
        return download_domains(HAGEZI_PRO_MINI_URL), "Hagezi Pro Mini", "pro_mini", False

    normal_domains = download_domains(HAGEZI_NORMAL_URL)
    pro_domains = download_domains(HAGEZI_PRO_URL)
    delta_domains = pro_domains - normal_domains
    prospective_total = len(normal_domains) + len(delta_domains) + whitelist_count

    if prospective_total < CAPACITY_DOWNGRADE_THRESHOLD:
        return pro_domains, "Hagezi Pro", "full_pro", False

    log(f"WARNING: Normal+Delta+Whitelist would be {prospective_total} domains this run, at or "
        f"above the {CAPACITY_DOWNGRADE_THRESHOLD}-domain safety threshold (Cloudflare's real cap "
        f"is {MAX_LISTS * CHUNK_SIZE}). Automatically switching the Personal policy's second "
        f"source from full Hagezi Pro to Hagezi Pro Mini to stay safely under the cap - same kind "
        f"of ad/tracker/malware/phishing coverage, a smaller curated domain set. This is a "
        f"one-way, permanent change: Personal keeps using Pro Mini on every future run, it does "
        f"not automatically switch back even if the list shrinks later.")
    return download_domains(HAGEZI_PRO_MINI_URL), "Hagezi Pro Mini", "pro_mini", True


def main():
    state = load_state()

    log("Downloading Hagezi Normal...")
    normal_domains = download_domains(HAGEZI_NORMAL_URL)
    if not normal_domains:
        die("Hagezi Normal download is empty")

    log("Fetching current Gateway lists (needed for the capacity check and the sync itself)...")
    current_lists = paginate("/gateway/lists")
    whitelist_count = sum(
        l.get("count", 0) for l in current_lists if l["name"].startswith(WHITELIST_PREFIX)
    )

    log("Resolving Hagezi Pro source (checking capacity safety valve)...")
    pro_domains, pro_label, mode, downgraded_this_run = resolve_pro_source(state, whitelist_count)
    if not pro_domains:
        die(f"{pro_label} download is empty")

    delta_domains = pro_domains - normal_domains
    if not delta_domains:
        die(f"{pro_label} delta is empty - something is wrong upstream")

    log(f"Hagezi Normal: {len(normal_domains)} domains")
    log(f"{pro_label} delta ({pro_label} minus Normal): {len(delta_domains)} domains")
    log(f"Whitelist: {whitelist_count} domains")
    log(f"Combined Normal+Delta+Whitelist target: "
        f"{len(normal_domains) + len(delta_domains) + whitelist_count} of "
        f"{MAX_LISTS * CHUNK_SIZE} max ({mode} mode)")

    normal_hash = sha256_of(normal_domains)
    delta_hash = sha256_of(delta_domains)
    if (not downgraded_this_run and state.get("normal_sha256") == normal_hash
            and state.get("delta_sha256") == delta_hash
            and state.get("blocklist_mode", "full_pro") == mode):
        log("No change in either source since the last successful sync. Nothing to do.")
        return

    log("Fetching current Gateway policies...")
    rules_resp = api("GET", "/gateway/rules")
    current_policies = rules_resp.get("result") if rules_resp else None
    if current_policies is None:
        # Unlike list items, getting this wrong is dangerous: if we mistakenly think no
        # policy exists, upsert_policy() would create a duplicate instead of updating.
        die(f"Fetching current Gateway policies returned no result body: {rules_resp}")

    normal_lists = sorted(
        (l for l in current_lists if l["name"].startswith(NORMAL_PREFIX)),
        key=lambda l: l["name"],
    )
    delta_lists = sorted(
        (l for l in current_lists if l["name"].startswith(DELTA_PREFIX)),
        key=lambda l: l["name"],
    )
    retired_lists = [l for l in current_lists if is_retired(l["name"])]
    non_retired_count = len(current_lists) - len(retired_lists)

    # The 300-list cap is enforced on the account's TOTAL list count, regardless of
    # whether a list is still referenced by a policy - a retired list still occupies a
    # slot until it's actually deleted. So the real headroom for new creates, as long as
    # we leave retired lists in place, is measured against the current total, not just
    # the "active" subset.
    budget = max(0, MAX_LISTS - len(current_lists))
    log(f"Account currently has {len(current_lists)} lists ({len(retired_lists)} retired, "
        f"{non_retired_count} active); {budget} of headroom before the {MAX_LISTS} cap "
        f"without touching retired lists.")

    # Retired lists still referenced by Personal's *current* traffic can't be deleted
    # until Personal is repointed away from them (Cloudflare rejects deleting a list
    # that's in active use by a rule). Anything retired but already unreferenced is dead
    # weight and safe to drop immediately regardless of budget.
    personal_policy = next((r for r in current_policies if r["name"] == "Personal"), None)
    personal_traffic = personal_policy.get("traffic", "") if personal_policy else ""
    referenced_retired = [l for l in retired_lists if f"${l['id']}" in personal_traffic]
    orphaned_retired = [l for l in retired_lists if l not in referenced_retired]

    if orphaned_retired:
        log(f"Deleting {len(orphaned_retired)} retired lists that are already unreferenced...")
        for l in orphaned_retired:
            api("DELETE", f"/gateway/lists/{l['id']}", fatal=False)
        budget = max(0, budget + len(orphaned_retired))
        retired_lists = referenced_retired

    # Upper-bound estimate of brand new lists this run could need (ignores free space in
    # lists we're about to patch, so it's pessimistic - real usage is normally far lower).
    worst_case_new = (
        max(0, -(-len(normal_domains) // CHUNK_SIZE) - len(normal_lists))
        + max(0, -(-len(delta_domains) // CHUNK_SIZE) - len(delta_lists))
    )

    if worst_case_new > budget and referenced_retired:
        # Repoint Personal at just the Normal lists first - a real, valid, zero-downtime
        # upgrade over the old OISD/Light setup on its own - which drops the reference to
        # the remaining retired lists and frees those slots for deletion. Personal gets
        # upgraded to the full Normal+Delta set a few steps later in this same run.
        log(f"Estimated worst case of {worst_case_new} new lists needed, only {budget} of "
            f"headroom available, and {len(referenced_retired)} retired lists are still "
            f"referenced by Personal's current policy. Repointing Personal at the "
            f"Normal-only list set first (a real upgrade on its own) to free them.")
        upsert_policy("Home", HOME_LOCATION_ID,
                      [l["id"] for l in normal_lists], current_policies)
        upsert_policy("Personal", PERSONAL_LOCATION_ID,
                      [l["id"] for l in normal_lists], current_policies)
        for l in referenced_retired:
            api("DELETE", f"/gateway/lists/{l['id']}", fatal=False)
        budget = max(0, MAX_LISTS - non_retired_count)
        retired_lists = []  # already gone - nothing left to delete again at the end
        # Refresh our view of "current" policies so the upsert_policy calls below see
        # Home/Personal as already existing (PUT, not POST).
        rules_resp = api("GET", "/gateway/rules")
        current_policies = (rules_resp or {}).get("result") or current_policies

    normal_ids, normal_empty, normal_created, budget = sync_list_set(
        NORMAL_PREFIX, normal_domains, normal_lists, budget)
    delta_ids, delta_empty, delta_created, budget = sync_list_set(
        DELTA_PREFIX, delta_domains, delta_lists, budget)

    upsert_policy("Home", HOME_LOCATION_ID, normal_ids, current_policies)
    upsert_policy("Personal", PERSONAL_LOCATION_ID, normal_ids + delta_ids, current_policies)

    # Only now that no policy references them anymore: drop empty lists + any leftover
    # retired lists (normally already gone via the early-free step above).
    to_delete = normal_empty + delta_empty + [l["id"] for l in retired_lists]
    log(f"Deleting {len(to_delete)} superseded/empty lists...")
    for lid in to_delete:
        api("DELETE", f"/gateway/lists/{lid}", fatal=False)

    new_state = {"normal_sha256": normal_hash, "delta_sha256": delta_hash, "blocklist_mode": mode}
    if downgraded_this_run:
        new_state["blocklist_mode_switched_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    elif "blocklist_mode_switched_at" in state:
        new_state["blocklist_mode_switched_at"] = state["blocklist_mode_switched_at"]
    save_state(new_state)

    actor = os.environ.get("GITHUB_ACTOR", "github-actions")
    actor_id = os.environ.get("GITHUB_ACTOR_ID", "41898282")
    git("config", "--global", "user.email", f"{actor_id}+{actor}@users.noreply.github.com")
    git("config", "--global", "user.name", actor)
    git("add", STATE_FILE)
    result = subprocess.run(["git", "diff", "--staged", "--quiet"])
    if result.returncode != 0:
        git("commit", "-m", "Update sync state")
        push = subprocess.run(["git", "push", "origin", "main"], capture_output=True, text=True)
        if push.returncode != 0:
            log(f"Warning: git push failed (state.json change-detection won't persist for "
                f"next run, but the Cloudflare sync above already completed successfully): "
                f"{push.stderr}")
        else:
            log("Pushed updated state.json.")
    else:
        log("Nothing to commit.")

    log("Done.")


def audit():
    """Read-only inventory of the account's current Gateway lists/policies. Makes no changes."""
    log("Fetching current Gateway policies...")
    for r in (api("GET", "/gateway/rules") or {}).get("result") or []:
        n_lists = r["traffic"].count("any(dns.domains")
        log(f"  policy {r['name']!r}: version {r['version']}, updated_at {r['updated_at']}, "
            f"references {n_lists} list(s)")

    log("Fetching current Gateway lists...")
    current_lists = paginate("/gateway/lists")
    by_bucket = {}
    for l in current_lists:
        if l["name"].startswith(NORMAL_PREFIX):
            bucket = NORMAL_PREFIX
        elif l["name"].startswith(DELTA_PREFIX):
            bucket = DELTA_PREFIX
        elif is_retired(l["name"]):
            bucket = "retired"
        else:
            bucket = "other"
        by_bucket.setdefault(bucket, []).append(l)

    log(f"Total lists: {len(current_lists)} (cap {MAX_LISTS})")
    for bucket, items in sorted(by_bucket.items()):
        log(f"  {bucket}: {len(items)} lists")
        for l in items[:3]:
            log(f"    e.g. {l['name']!r} ({l['id']}, {l.get('count', '?')} items)")


if __name__ == "__main__":
    if "--audit" in sys.argv:
        audit()
    else:
        main()
