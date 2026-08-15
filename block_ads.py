#!/usr/bin/env python3
"""
Home + Personal Cloudflare Gateway blocklist sync — config driven.

WHAT CHANGED FROM THE PREVIOUS VERSION
--------------------------------------
The sources used to be hardcoded: Home got Hagezi Normal, Personal got Hagezi
Normal plus a Hagezi Pro "delta". They are now read from blocklists.json in this
repo, which the Zamir Residence Dashboard commits when you pick lists in the
app. Everything else about how the sync behaves is deliberately unchanged — the
in-place diff/PATCH strategy, the compaction pass, the 300-list budget guard and
the mirror fallbacks all work exactly as before, because those are the parts
that keep the house protected while a run is in flight.

If blocklists.json is missing or unreadable this falls back to the old hardcoded
pairing, so the repo keeps working untouched.

HOW THE TWO NETWORKS SHARE STORAGE
----------------------------------
Cloudflare charges per domain stored, not per policy that references it, so the
domains both networks block are stored once and referenced twice. Every run
partitions the combined selection into three tiers:

    shared         — -> both the Home and Personal policies
    home-only      — -> the Home policy
    personal-only  — -> the Personal policy

Under the previous hardcoded setup that partition came out as exactly
"Hagezi Normal" and "Hagezi Pro delta" with nothing home-only, which is why the
existing Lists map onto the new scheme with no churn. See migrate_prefixes().

PARENT COLLAPSING
-----------------
Gateway blocks a listed domain and every subdomain beneath it, so an entry whose
parent is already covered is dead weight. This is applied WITHIN a network's own
set, and to drop from a network's private tier anything the shared tier already
covers — never across the two networks, which would silently unprotect whichever
network doesn't own the parent. See partition().

Usage:
    python3 block_ads.py              # normal run
    python3 block_ads.py --dry-run    # download, plan, print — touches nothing
    python3 block_ads.py --audit      # read-only inventory
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DRY_RUN = "--dry-run" in sys.argv

API_TOKEN = os.environ.get("API_TOKEN", "")
ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"

CHUNK_SIZE = 1000          # domains per Cloudflare list
PATCH_BATCH = 1000         # domains per single PATCH append/remove call
MAX_LISTS = 300            # empirically-verified enforced cap on this account

# Don't repack a tier unless it frees at least this many List slots. Compaction
# costs two PATCH calls per 1,000 domains moved; reclaiming one or two slots
# every run is churn for its own sake, five or more is real headroom.
COMPACT_MIN_RECLAIM = 5

HOME_LOCATION_IDS = ["3d4d56f8749d41ea97d291ec5faf3de7"]          # eero

# Every personal DNS location. Each device has its OWN Gateway location -- that
# is the only thing that distinguishes a Mac query from an iPhone one, because
# Cloudflare's DNS analytics carries no per-device identity (the dataset exposes
# locationId and dohSubdomain, but no email/userId/deviceId).
#
# CRITICAL: upsert_policy rebuilds the Personal policy's traffic expression from
# scratch on every run. Any location missing from this list is dropped from the
# policy on the next sync, and that device silently stops being filtered -- no
# error, no failed run, it just quietly goes unprotected. Add a location here the
# moment you create it.
PERSONAL_LOCATION_IDS = [
    "64da928fcda94b808adc11b4f036d7dd",  # Hamza's MacBook Pro
    "9932efe4cf894d76a588ca00b4e08c98",  # Hamza's iPhone
    "37dbdba0d3ca4288820a0243d7a252c2",  # Hamza's iPad
    "6b497a05ed454984b33cbf3554ca544b",  # Personal (before split) -- pre-split history
]

CONFIG_FILE = "blocklists.json"
STATE_FILE = "state.json"

# The three tiers. SHARED_PREFIX and PERSONAL_PREFIX are the strings the old
# Normal / ProDelta Lists get renamed to on first run — not new names for new
# Lists. See migrate_prefixes() for why renaming beats recreating.
SHARED_PREFIX = "Block ads - Shared"
HOME_PREFIX = "Block ads - Home"
PERSONAL_PREFIX = "Block ads - Personal"
WHITELIST_PREFIX = "Allow - Whitelist"

# What the previous hardcoded version of this script called those two tiers.
LEGACY_SHARED_PREFIX = "Block ads - Hagezi Normal"
LEGACY_PERSONAL_PREFIX = "Block ads - Hagezi ProDelta"

MANAGED_PREFIXES = (SHARED_PREFIX, HOME_PREFIX, PERSONAL_PREFIX)

HAGEZI_MIRRORS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/",
    "https://hagezi-mirror.dnsbunker.org/wildcard/",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/",
]

# Used only when blocklists.json is absent — byte-for-byte the behaviour of the
# version of this script that predates the config file.
DEFAULT_CONFIG = {
    "networks": {
        "home": ["hagezi-multi"],
        "personal": ["hagezi-pro"],
    },
    "sources": {
        "hagezi-multi": {
            "name": "Hagezi Normal",
            "urls": [b + "multi-onlydomains.txt" for b in HAGEZI_MIRRORS],
            "format": "domains",
            "min_domains": 100_000,
        },
        "hagezi-pro": {
            "name": "Hagezi Pro",
            "urls": [b + "pro-onlydomains.txt" for b in HAGEZI_MIRRORS],
            "format": "domains",
            "min_domains": 120_000,
        },
    },
}

# Once a prospective sync would put the account at or above this, stop before
# changing anything. The real cap is 300,000; the app refuses to commit a
# selection that doesn't fit, so reaching this means the upstream lists grew
# after the selection was made. Failing loudly is correct — silently swapping in
# a list the user didn't choose would be worse.
CAPACITY_THRESHOLD = 299_000


def log(msg):
    print(msg, flush=True)


def die(msg):
    print(f"Error: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Cloudflare API
# ---------------------------------------------------------------------------

def api(method, path, data=None, retries=6, fatal=True):
    if DRY_RUN and method != "GET":
        log(f"  [dry-run] would {method} {path}"
            + (f" ({len(data.get('append', data.get('remove', data.get('items', [])))) } items)"
               if isinstance(data, dict) else ""))
        return {"result": {"id": "dry-run-id"}}

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
            # Cloudflare sometimes returns HTTP 200 with a logical failure in the
            # body — "result" is null in that case, which would blow up callers
            # that expect a list/dict.
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
            log(f"Warning: {path} page {page} returned no result body, treating as empty/last page")
            break
        results.extend(batch)
        # result_info exposes total_count, not total_pages — a short page is the
        # last page.
        if len(batch) < per_page:
            break
        page += 1
    return results


def chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
#
# Parsing must stay in lockstep with backend/blocklists.py's parse_domains in
# the dashboard repo — the app plans capacity with its parser and this script
# builds the Lists with this one, so a disagreement shows up as the app
# promising a fit that doesn't materialise.

_HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)")
_ADBLOCK_RE = re.compile(r"^\|\|([a-z0-9.\-_*]+)\^(?:\$[a-z,~=|.\-]+)?$", re.I)
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9\-_]{1,63}(?<!-)(\.(?!-)[a-z0-9\-_]{1,63}(?<!-))+$", re.I)
_IGNORED_HOSTS = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
                  "ip6-loopback", "ip6-allnodes", "ip6-allrouters", "0.0.0.0"}


def parse_domains(text, fmt):
    out = set()
    version = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line[0] in "#![":
            if version is None and line.lower().startswith("# version:"):
                version = line.split(":", 1)[1].strip()
            continue
        if fmt == "hosts":
            m = _HOSTS_RE.match(line)
            if not m:
                continue
            value = m.group(1)
        elif fmt == "adblock":
            m = _ADBLOCK_RE.match(line)
            if not m:
                continue
            value = m.group(1)
        else:
            value = line.split()[0]
        value = value.strip().lower().rstrip(".")
        if value.startswith("*."):
            value = value[2:]
        if not value or value in _IGNORED_HOSTS or not _DOMAIN_RE.match(value):
            continue
        out.add(value)
    return out, version


def download_source(source_id, spec, retries=3):
    """Fetch one configured source from the first mirror clearing its floor.

    The floor exists for a specific failure mode: a mirror answering HTTP 200
    with an error page parses as a nearly-empty list, and because this script
    syncs by diffing it would then dutifully DELETE the real domains out of
    Cloudflare and leave the house unprotected.
    """
    floor = int(spec.get("min_domains") or 1)
    fmt = spec.get("format", "domains")
    failures = []
    for url in spec.get("urls") or []:
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
                with urllib.request.urlopen(req, timeout=90) as resp:
                    text = resp.read().decode(errors="ignore")
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                failures.append(f"{url}: {e}")
                break
            domains, version = parse_domains(text, fmt)
            if len(domains) < floor:
                failures.append(f"{url}: only {len(domains)} domains, below the {floor} sanity floor")
                break
            log(f"  {spec.get('name', source_id)}: {len(domains)} domains from {url} "
                f"(version {version or 'unknown'})")
            return domains
    die(f"Could not download {spec.get('name', source_id)} from any mirror:\n  " + "\n  ".join(failures))


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
            networks = cfg.get("networks") or {}
            sources = cfg.get("sources") or {}
            if sources and (networks.get("home") or networks.get("personal")):
                log(f"Using selection from {CONFIG_FILE} "
                    f"(updated {cfg.get('updated_at', 'unknown')} by {cfg.get('updated_by', 'unknown')})")
                return {"networks": networks, "sources": sources}
            log(f"Warning: {CONFIG_FILE} is present but empty or malformed; using the built-in default.")
        except Exception as e:
            log(f"Warning: could not read {CONFIG_FILE} ({e}); using the built-in default.")
    else:
        log(f"No {CONFIG_FILE} in the repo yet; using the built-in default selection.")
    return DEFAULT_CONFIG


def is_covered_by(domain, domains):
    """True when `domains` blocks `domain` — directly or via a parent."""
    parts = domain.split(".")
    return any(".".join(parts[i:]) in domains for i in range(len(parts) - 1))


def collapse_to_parents(domains):
    """Drop entries whose parent is also in the SAME set — Gateway already
    blocks every subdomain of a listed domain, so those buy nothing.

    Only ever applied within one network's set. Collapsing across both networks
    is wrong: it drops a domain from Home because Personal's list holds its
    parent, and Home's policy does not reference Personal's lists.
    """
    out = set()
    for domain in domains:
        parts = domain.split(".")
        if any(".".join(parts[i:]) in domains for i in range(1, len(parts) - 1)):
            continue
        out.add(domain)
    return out


def partition(home, personal):
    """Three storage tiers. Must match backend/blocklists.py's partition()
    exactly — the app promises a capacity result from that function and this one
    has to deliver it.

    Only domains BOTH networks want may be shared; promoting a parent only one
    network asked for would make the other over-block. A domain is dropped from
    a network's own tier when the shared tier already covers it, since every
    network references shared.
    """
    home = collapse_to_parents(home)
    personal = collapse_to_parents(personal)
    shared = collapse_to_parents(home & personal)
    home_only = {d for d in home - shared if not is_covered_by(d, shared)}
    personal_only = {d for d in personal - shared if not is_covered_by(d, shared)}
    return shared, home_only, personal_only


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


# ---------------------------------------------------------------------------
# List maintenance
# ---------------------------------------------------------------------------

def migrate_prefixes(current_lists):
    """Rename the old hardcoded-era Lists onto the three-tier scheme, in place.

    The previous version of this script named its Lists after the specific
    Hagezi tiers it hardcoded. Those names are wrong the moment a different
    source is selected, but recreating ~225 Lists under new names is not an
    option: two generations cannot coexist under the 300-list cap, and deleting
    first means an outage for the minutes it takes to rebuild.

    Cloudflare's list PATCH accepts a name, so the Lists are renamed where they
    stand. Contents, ids and policy references are all untouched — the policies
    keep pointing at the same list ids throughout.

    The old tiers map onto the new ones exactly, which is not a coincidence:
    under the old pairing Home's set was a subset of Personal's, so the
    partition this script now computes produces "everything Home has" (the old
    Normal tier) and "what only Personal has" (the old ProDelta tier), with
    nothing home-only.
    """
    # Never let a legacy-named list fall through to the retirement logic. If a
    # rename fails, the list keeps its old name — and is_retired() would then
    # classify it as dead weight and DELETE it, taking the domains with it and
    # rebuilding from scratch. That is a real outage plus a cap risk, from a
    # single failed PATCH. Abort instead; see the check at the end.
    renames = []
    for lst in current_lists:
        name = lst["name"]
        if name.startswith(LEGACY_SHARED_PREFIX):
            renames.append((lst, name.replace(LEGACY_SHARED_PREFIX, SHARED_PREFIX, 1)))
        elif name.startswith(LEGACY_PERSONAL_PREFIX):
            renames.append((lst, name.replace(LEGACY_PERSONAL_PREFIX, PERSONAL_PREFIX, 1)))
    if not renames:
        return current_lists

    log(f"Migrating {len(renames)} lists from the old naming scheme to the three-tier scheme...")
    failed = []
    for lst, new_name in renames:
        # PUT, not PATCH. Cloudflare's Gateway-list PATCH is for items only: it
        # accepts a "name" field, answers success=true, and silently ignores it
        # (verified live — 228 lists reported renamed, zero actually were). PUT
        # with {name, type} does rename, and leaves the items untouched
        # (verified on a throwaway list: both items survived).
        resp = api("PUT", f"/gateway/lists/{lst['id']}", {"name": new_name, "type": "DOMAIN"}, fatal=False)
        got = ((resp or {}).get("result") or {}).get("name")
        if got != new_name:
            # Never trust the call — confirm the server echoed the new name.
            # Believing an ignored rename is exactly how the first attempt
            # produced a log full of successes and an unchanged account.
            failed.append(f"{lst['name']} (server said {got!r})")
            continue
        lst["name"] = new_name
    if failed:
        die(f"Renamed {len(renames) - len(failed)} of {len(renames)} lists, but {len(failed)} "
            f"failed (e.g. {failed[0]!r}). Stopping before touching anything else — a "
            f"half-migrated account would have the still-old-named lists deleted as retired. "
            f"Re-run to retry; the renames already done are harmless and idempotent.")
    log("Rename complete — contents and list ids unchanged, policies never dereferenced.")
    return current_lists


def is_retired(name):
    """True for lists from naming schemes nothing references anymore. These are
    deleted outright rather than diffed.

    The legacy prefixes are deliberately excluded even though migrate_prefixes()
    should have renamed them already. If a rename ever fails, treating the
    survivors as retired would delete live blocklists and rebuild them from
    empty — so the safe answer is to leave them alone and let the run abort on
    the list budget instead.
    """
    if any(name.startswith(p) for p in MANAGED_PREFIXES):
        return False
    if name.startswith((WHITELIST_PREFIX, LEGACY_SHARED_PREFIX, LEGACY_PERSONAL_PREFIX)):
        return False
    return name.startswith("Block ads - ")


def reclaimable_slots(current_lists):
    """How many List slots a repack would hand back, per managed tier, using only
    the `count` the list endpoint already returns."""
    total = 0
    for prefix in MANAGED_PREFIXES:
        tier = [l for l in current_lists if l["name"].startswith(prefix)]
        if not tier:
            continue
        domains = sum(l.get("count", 0) or 0 for l in tier)
        perfect = (domains + CHUNK_SIZE - 1) // CHUNK_SIZE
        total += max(0, len(tier) - perfect)
    return total


def compact_lists(prefix, current_map):
    """Repack a tier's Lists so the same domains occupy as few Lists as possible.

    The diff/PATCH sync never lets a List grow past CHUNK_SIZE, but nothing ever
    pushed a List back up toward full once churn had eaten into it. Every run
    removes domains scattered across every List and adds a smaller number back,
    so the holes punched by removals were never fully backfilled — a one-way
    ratchet toward small-but-nonzero Lists. Observed before this existed: 277 of
    300 Lists holding 224,261 domains, i.e. an account that looked 92% full
    while being 75% empty.

    Domains are APPENDED to the receiver before being REMOVED from the donor,
    never the reverse. A run that dies mid-move leaves a domain in two Lists —
    harmless duplicate blocking the next diff cleans up. The other order could
    leave it in neither, i.e. silently unblocked.
    """
    placed = set()
    for domains in current_map.values():
        placed |= domains
    needed = (len(placed) + CHUNK_SIZE - 1) // CHUNK_SIZE
    reclaimable = len(current_map) - needed
    if reclaimable < COMPACT_MIN_RECLAIM:
        log(f"[{prefix}] packing is fine — {len(current_map)} lists for {len(placed)} domains "
            f"(a perfect pack would need {needed}); not worth the API churn.")
        return 0

    by_fill = sorted(current_map, key=lambda lid: len(current_map[lid]), reverse=True)
    receivers, donors = by_fill[:needed], by_fill[needed:]
    free = sum(CHUNK_SIZE - len(current_map[r]) for r in receivers)

    drained = []
    used = 0
    for d in sorted(donors, key=lambda lid: len(current_map[lid])):
        if used + len(current_map[d]) <= free:
            drained.append(d)
            used += len(current_map[d])
    if not drained:
        return 0

    moving = []
    for d in drained:
        moving.extend(sorted(current_map[d]))

    log(f"[{prefix}] compacting: {len(current_map)} lists hold {len(placed)} domains "
        f"(perfect pack = {needed}); moving {len(moving)} domains to drain {len(drained)} lists.")

    for r in receivers:
        if not moving:
            break
        space = CHUNK_SIZE - len(current_map[r])
        if space <= 0:
            continue
        take = [d for d in moving[:space] if d not in current_map[r]]
        moving = moving[space:]
        for batch in chunks(take, PATCH_BATCH):
            api("PATCH", f"/gateway/lists/{r}", {"append": [{"value": d} for d in batch]})
        current_map[r] |= set(take)

    for d in drained:
        for batch in chunks(sorted(current_map[d]), PATCH_BATCH):
            api("PATCH", f"/gateway/lists/{d}", {"remove": batch})
        current_map[d] = set()

    log(f"[{prefix}] compaction drained {len(drained)} lists; they will be deleted "
        f"once the policies no longer reference them.")
    return len(drained)


def sync_list_set(prefix, target_domains, existing_lists, budget):
    """Diff/PATCH a tier's Lists so their combined contents equal target_domains,
    creating new Lists only for overflow that doesn't fit in existing ones.

    Returns (kept_ids, empty_ids, lists_created, budget_remaining).
    """
    current_map = {}
    for lst in existing_lists:
        items = paginate(f"/gateway/lists/{lst['id']}/items")
        current_map[lst["id"]] = {i["value"] for i in items}
        time.sleep(0.05)  # light throttle — avoid bursting hundreds of GETs

    all_current = set()
    for domains in current_map.values():
        all_current |= domains

    to_add = list(target_domains - all_current)
    to_remove = all_current - target_domains

    log(f"[{prefix}] existing lists: {len(existing_lists)}, current domains: {len(all_current)}, "
        f"target domains: {len(target_domains)}, to add: {len(to_add)}, to remove: {len(to_remove)}")

    for lst in existing_lists:
        lid = lst["id"]
        remove_here = list(current_map[lid] & to_remove)
        for batch in chunks(remove_here, PATCH_BATCH):
            # Patch List takes `remove` as plain value strings but `append` as
            # full {"value": ...} objects — these are NOT symmetric.
            api("PATCH", f"/gateway/lists/{lid}", {"remove": batch})
        if remove_here:
            current_map[lid] -= set(remove_here)

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

    # Backfilling only moves domains into holes as big as this run's add queue.
    # Anything left is long-run fragmentation — repack before creating, so a slot
    # freed here is a slot creation can spend instead of failing against the cap.
    compact_lists(prefix, current_map)

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


# Security Threats and DNS Rebinding Protection are SEPARATE Gateway rules,
# deliberately not folded into this traffic expression. Folding them in broke the
# dashboard's ability to filter for them: Cloudflare's free analytics API can only
# filter the query log by policyName, so buried inside Home/Personal they became
# unretrievable. This function fully rebuilds Home/Personal's traffic each run,
# so anything added here would be wiped every sync anyway.
def build_traffic(location_ids, list_ids):
    clauses = " or ".join(f"any(dns.domains[*] in ${lid})" for lid in list_ids)
    locations = " ".join(f'"{lid}"' for lid in location_ids)
    return f'dns.location in {{{locations}}} and ({clauses})'


def upsert_policy(name, location_ids, list_ids, current_policies):
    if not list_ids:
        log(f"Skipping policy {name} — its selection resolved to no lists.")
        return
    # Refuse rather than write a policy covering nothing: an empty location set
    # produces `dns.location in {}`, which matches no query at all and would
    # disable this policy account-wide without failing the run.
    if not location_ids:
        raise SystemExit(f"Policy {name} has no location ids configured — refusing to write a policy that matches nothing.")
    traffic = build_traffic(location_ids, list_ids)
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
        log(f"Updating policy {name} ({existing['id']}) -> {len(list_ids)} lists...")
        api("PUT", f"/gateway/rules/{existing['id']}", payload)


def git(*args):
    subprocess.run(["git", *args], check=True)


# ---------------------------------------------------------------------------

def resolve_selection(config):
    """Download every configured source and partition the result into the three
    storage tiers. Returns (shared, home_only, personal_only, source_versions)."""
    networks = config["networks"]
    specs = config["sources"]
    wanted = []
    for network in ("home", "personal"):
        for source_id in networks.get(network) or []:
            if source_id not in specs:
                die(f"{CONFIG_FILE} lists source '{source_id}' for {network} but has no "
                    f"definition for it under \"sources\".")
            if source_id not in wanted:
                wanted.append(source_id)

    if not wanted:
        die(f"{CONFIG_FILE} selects no blocklists at all.")

    log("Downloading selected sources...")
    fetched = {sid: download_source(sid, specs[sid]) for sid in wanted}

    home = set().union(*[fetched[s] for s in networks.get("home") or []]) if networks.get("home") else set()
    personal = (set().union(*[fetched[s] for s in networks.get("personal") or []])
                if networks.get("personal") else set())

    before = len(home | personal)
    shared, home_only, personal_only = partition(home, personal)
    kept = len(shared) + len(home_only) + len(personal_only)
    log(f"Parent collapsing removed {before - kept} redundant subdomain entries ({kept} remain).")
    return shared, home_only, personal_only


def main():
    if not DRY_RUN and (not API_TOKEN or not ACCOUNT_ID):
        die("API_TOKEN and ACCOUNT_ID must be set.")

    state = load_state()
    config = load_config()
    networks = config["networks"]
    log(f"Home     -> {', '.join(networks.get('home') or []) or '(none)'}")
    log(f"Personal -> {', '.join(networks.get('personal') or []) or '(none)'}")

    shared, home_only, personal_only = resolve_selection(config)

    log("Fetching current Gateway lists...")
    current_lists = paginate("/gateway/lists") if not DRY_RUN or ACCOUNT_ID else []
    whitelist_count = sum(
        l.get("count", 0) for l in current_lists if l["name"].startswith(WHITELIST_PREFIX)
    )

    total = len(shared) + len(home_only) + len(personal_only) + whitelist_count
    needed_lists = sum(-(-len(s) // CHUNK_SIZE) for s in (shared, home_only, personal_only))
    log(f"Shared: {len(shared)}  Home-only: {len(home_only)}  Personal-only: {len(personal_only)}  "
        f"Whitelist: {whitelist_count}")
    log(f"Combined target: {total} domains in ~{needed_lists} lists "
        f"(cap {MAX_LISTS * CHUNK_SIZE} domains / {MAX_LISTS} lists)")

    if total >= CAPACITY_THRESHOLD or needed_lists > MAX_LISTS:
        die(f"This selection needs {total} domains across ~{needed_lists} lists, at or above the "
            f"{CAPACITY_THRESHOLD}-domain safety threshold. Nothing has been changed. Pick a "
            f"smaller combination in the dashboard — the sources have grown since it was chosen.")

    if DRY_RUN:
        log("\n[dry-run] Plan is valid and fits. No Cloudflare changes were made.")
        return

    current_lists = migrate_prefixes(current_lists)

    tiers = [
        (SHARED_PREFIX, shared),
        (HOME_PREFIX, home_only),
        (PERSONAL_PREFIX, personal_only),
    ]

    selection_hash = hashlib.sha256(
        json.dumps(networks, sort_keys=True).encode()).hexdigest()
    tier_hashes = {prefix: sha256_of(domains) for prefix, domains in tiers}
    reclaimable = reclaimable_slots(current_lists)

    if (state.get("selection_sha256") == selection_hash
            and state.get("tier_sha256") == tier_hashes
            and reclaimable < COMPACT_MIN_RECLAIM):
        log("No change in the selection or any source since the last successful sync, and the "
            "lists are well packed. Nothing to do.")
        return
    if reclaimable >= COMPACT_MIN_RECLAIM:
        log(f"Lists are fragmented — about {reclaimable} of the {MAX_LISTS} slots are "
            f"reclaimable by repacking. Running a sync to compact them.")

    log("Fetching current Gateway policies...")
    rules_resp = api("GET", "/gateway/rules")
    current_policies = rules_resp.get("result") if rules_resp else None
    if current_policies is None:
        # Getting this wrong is dangerous: believing no policy exists would make
        # upsert_policy create a duplicate instead of updating.
        die(f"Fetching current Gateway policies returned no result body: {rules_resp}")

    retired_lists = [l for l in current_lists if is_retired(l["name"])]

    # The cap counts every list, referenced or not — a retired list occupies a
    # slot until it is actually deleted.
    budget = max(0, MAX_LISTS - len(current_lists))
    log(f"Account has {len(current_lists)} lists ({len(retired_lists)} retired); "
        f"{budget} of headroom before the {MAX_LISTS} cap.")

    # Retired lists still referenced by a policy can't be deleted until that
    # policy is repointed (Cloudflare rejects deleting a list in active use).
    referenced = ""
    for rule in current_policies:
        if rule.get("name") in ("Home", "Personal"):
            referenced += rule.get("traffic", "") or ""
    orphaned_retired = [l for l in retired_lists if f"${l['id']}" not in referenced]
    if orphaned_retired:
        log(f"Deleting {len(orphaned_retired)} retired lists that are already unreferenced...")
        for l in orphaned_retired:
            api("DELETE", f"/gateway/lists/{l['id']}", fatal=False)
        budget += len(orphaned_retired)
        retired_lists = [l for l in retired_lists if l not in orphaned_retired]

    tier_ids, tier_empty = {}, []
    for prefix, domains in tiers:
        existing = sorted((l for l in current_lists if l["name"].startswith(prefix)),
                          key=lambda l: l["name"])
        kept, empty, _created, budget = sync_list_set(prefix, domains, existing, budget)
        tier_ids[prefix] = kept
        tier_empty.extend(empty)

    upsert_policy("Home", HOME_LOCATION_IDS,
                  tier_ids[SHARED_PREFIX] + tier_ids[HOME_PREFIX], current_policies)
    upsert_policy("Personal", PERSONAL_LOCATION_IDS,
                  tier_ids[SHARED_PREFIX] + tier_ids[PERSONAL_PREFIX], current_policies)

    # Only now that no policy references them: drop empty and retired lists.
    to_delete = tier_empty + [l["id"] for l in retired_lists]
    log(f"Deleting {len(to_delete)} superseded/empty lists...")
    for lid in to_delete:
        api("DELETE", f"/gateway/lists/{lid}", fatal=False)

    new_state = {
        "selection_sha256": selection_hash,
        "tier_sha256": tier_hashes,
        "networks": networks,
        "domains": {"shared": len(shared), "home_only": len(home_only),
                    "personal_only": len(personal_only)},
        "synced_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    save_state(new_state)

    actor = os.environ.get("GITHUB_ACTOR", "github-actions")
    actor_id = os.environ.get("GITHUB_ACTOR_ID", "41898282")
    git("config", "--global", "user.email", f"{actor_id}+{actor}@users.noreply.github.com")
    git("config", "--global", "user.name", actor)
    git("add", STATE_FILE)
    result = subprocess.run(["git", "diff", "--staged", "--quiet"])
    if result.returncode != 0:
        git("commit", "-m", "Update sync state")
        # Rebase before pushing. The dashboard commits blocklists.json to this
        # same branch, so a selection saved while a sync is in flight makes the
        # push non-fast-forward and state.json silently fails to persist — which
        # then makes the next run redo everything and the app report a sync
        # script that looks out of date. Observed on the first real run.
        subprocess.run(["git", "pull", "--rebase", "origin", "main"], capture_output=True, text=True)
        push = subprocess.run(["git", "push", "origin", "main"], capture_output=True, text=True)
        if push.returncode != 0:
            log(f"Warning: git push failed (change-detection won't persist for the next run, but "
                f"the Cloudflare sync above already completed successfully): {push.stderr}")
        else:
            log("Pushed updated state.json.")
    else:
        log("Nothing to commit.")

    log("Done.")


def audit():
    """Read-only inventory of the account's current Gateway lists/policies."""
    log("Fetching current Gateway policies...")
    for r in (api("GET", "/gateway/rules") or {}).get("result") or []:
        n_lists = r["traffic"].count("any(dns.domains")
        log(f"  policy {r['name']!r}: version {r['version']}, updated_at {r['updated_at']}, "
            f"references {n_lists} list(s)")

    log("Fetching current Gateway lists...")
    current_lists = paginate("/gateway/lists")
    by_bucket = {}
    for l in current_lists:
        bucket = "other"
        for prefix in MANAGED_PREFIXES + (WHITELIST_PREFIX,):
            if l["name"].startswith(prefix):
                bucket = prefix
                break
        else:
            if is_retired(l["name"]):
                bucket = "retired"
        by_bucket.setdefault(bucket, []).append(l)

    log(f"Total lists: {len(current_lists)} (cap {MAX_LISTS})")
    for bucket, items in sorted(by_bucket.items()):
        domains = sum(i.get("count", 0) or 0 for i in items)
        log(f"  {bucket}: {len(items)} lists, {domains} domains")


if __name__ == "__main__":
    if "--audit" in sys.argv:
        audit()
    else:
        main()
