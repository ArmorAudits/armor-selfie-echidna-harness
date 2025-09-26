#!/usr/bin/env python3
import os, csv, base64, re, json, argparse
import requests

INTERESTING = (
    r"(?:^|/)(package\.json|requirements\.txt|pyproject\.toml|Pipfile|Pipfile\.lock|"
    r"Cargo\.toml|foundry\.toml|Dockerfile|dockerfile|go\.mod|\.tool-versions|"
    r"\.github/workflows/[^/]+\.ya?ml)$"
)
PAT = re.compile(INTERESTING, re.I)

DETECTORS = [
    (r'\bslither\b',                          "Slither"),
    (r'\bechidna\b|ghcr\.io/crytic/echidna',  "Echidna"),
    (r'\bmythril\b',                          "Mythril"),
    (r'\bmanticore\b',                        "Manticore"),
    (r'\bmedusa\b',                           "Medusa"),
    (r'\bhalmos\b',                           "Halmos"),
    (r'\bcertora[-_ ]?cli\b|\bcertora-cli\b', "certora-cli"),
    (r'\bsolc-select\b',                      "solc-select"),
    (r'\bsolc\b',                             "solc"),
    (r'\bforge\b|\bcast\b|\banvil\b',         "Foundry (forge/cast/anvil)"),
    (r'\bhardhat\b',                          "Hardhat"),
    (r'\btruffle\b',                          "Truffle"),
    (r'\bbrownie\b',                          "Brownie"),
    (r'\bape(\W|$)|\bApeWorx\b',              "ApeWorx (Ape)"),
    (r'\bsolhint\b',                          "Solhint"),
    (r'\bsolidity-coverage\b',                "Solidity Coverage"),
    (r'\babigen\b',                           "abigen (go-ethereum)"),
    (r'\bgeth\b',                             "geth"),
    (r'\bnethermind\b',                       "Nethermind"),
    (r'\berigon\b',                           "Erigon"),
    (r'\bganache\b',                          "Ganache"),
    (r'\bopenzeppelin[- ]contracts\b',        "OpenZeppelin Contracts"),
    (r'\bsafe[- ]?cli\b',                     "Safe CLI"),
    (r'\bdefender\b',                         "OpenZeppelin Defender"),
    (r'\btenderly\b',                         "Tenderly"),
    (r'\bsourcify\b',                         "Sourcify"),
    (r'\bgoal\b',                             "goal"),
    (r'\bpyteal\b',                           "PyTeal"),
    (r'\baptos[- ]?cli\b|\baptos-cli\b|\baptos\b', "aptos-cli"),
    (r'\bcosmos[- ]?sdk\b',                   "Cosmos SDK"),
    (r'\bgaiad\b',                            "Gaiad"),
    (r'\bhermes\b',                           "Hermes (IBC)"),
    (r'\bignite\b',                           "Ignite CLI"),
    (r'\banchor\b',                           "Anchor"),
    (r'\bspl[- ]?token\b|\bspl-token\b',      "SPL Token CLI"),
    (r'\bsolana[- ]?cli\b|\bsolana program\b',"Solana CLI"),
    (r'\bseahorse\b',                         "Seahorse"),
    (r'\bsolang\b',                           "Solang"),
    (r'\bscarb\b|\bcairo\b',                  "Cairo 1 / scarb"),
    (r'\bkatana\b',                           "katana (dojo)"),
    (r'\bstarknet[- ]?foundry\b|\bsnf\b',     "starknet Foundry"),
    (r'\bcargo[- ]?contract\b',               "cargo-contract"),
    (r'\bink!\b|\bink\b',                     "ink!"),
    (r'\bpolkadot\b',                         "polkadot"),
    (r'\bsui[- ]?cli\b|\bsui\b',              "sui-cli"),
    (r'\bnear[- ]?cli\b',                     "near-cli"),
    (r'\bSmartPy\b|\bsmartpy\b',              "SmartPy"),
    (r'\bligo\b',                             "LIGO"),
    (r'\bgitleaks\b',                         "gitleaks"),
    (r'\bdocker\b',                           "Docker"),
    (r'\bactions/checkout\b|\bgithub actions\b', "GitHub Actions"),
    (r'\bgh\b',                               "gh (GitHub CLI)"),
    (r'\bgit\b',                              "git"),
]

def _headers():
    t = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    h = {"Accept": "application/vnd.github+json", "User-Agent": "armor-ai-diff"}
    if t:
        h["Authorization"] = f"Bearer {t}"
    return h

def gh(url):
    r = requests.get(url, headers=_headers(), timeout=20)
    r.raise_for_status()
    return r.json()

def gh_b64(url):
    r = requests.get(url, headers=_headers(), timeout=20)
    r.raise_for_status()
    j = r.json()
    if isinstance(j, dict) and j.get("encoding") == "base64":
        import base64
        return base64.b64decode(j["content"]).decode("utf-8", "ignore")
    return ""

def list_repos_for(owner):
    out = []
    for kind in ("orgs", "users"):
        page = 1
        while True:
            res = requests.get(
                f"https://api.github.com/{kind}/{owner}/repos",
                params={"per_page": 100, "page": page},
                headers=_headers(), timeout=20,
            )
            if res.status_code == 404:
                break
            res.raise_for_status()
            batch = res.json()
            if not batch:
                break
            out.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        if out:
            return out
    return out

def default_branch_sha(owner, repo, default_branch):
    b = gh(f"https://api.github.com/repos/{owner}/{repo}/branches/{default_branch}")
    return b["commit"]["sha"]

def walk_tree(owner, repo, sha):
    t = gh(f"https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}?recursive=1")
    return [e for e in t.get("tree", []) if e.get("type") == "blob"]

def detect_tools_in_text(text):
    found = set()
    for rx, name in DETECTORS:
        if re.search(rx, text, flags=re.I):
            found.add(name)
    return found

def fetch_and_detect(owner, repo, path, ref):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    try:
        txt = gh_b64(url)
        return detect_tools_in_text(txt)
    except requests.HTTPError:
        return set()

def load_inventory(path):
    tools = set()
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            name = (row.get("Tool") or "").strip()
            if name:
                tools.add(name)
    return tools

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--orgs", required=True, help="Comma-separated orgs/users")
    ap.add_argument("--outdir", default="artifacts")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    inventory = load_inventory(args.inventory)

    discovered = []
    seen_tools = set()

    for who in [s.strip() for s in args.orgs.split(",") if s.strip()]:
        repos = list_repos_for(who)
        for r in repos:
            owner = r["owner"]["login"]
            repo  = r["name"]
            ref   = r["default_branch"]
            try:
                sha = default_branch_sha(owner, repo, ref)
                tree = walk_tree(owner, repo, sha)
            except requests.HTTPError:
                continue

            interesting_paths = [e["path"] for e in tree if PAT.search(e["path"])]
            for pth in interesting_paths:
                tools = fetch_and_detect(owner, repo, pth, ref)
                for tname in tools:
                    discovered.append({"Tool": tname, "Repo": f"{owner}/{repo}", "Path": pth})
                    seen_tools.add(tname)

    disc_csv = os.path.join(args.outdir, "github_tools_detected.csv")
    with open(disc_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["Tool","Repo","Path"])
        w.writeheader()
        for row in sorted(discovered, key=lambda x:(x["Tool"],x["Repo"],x["Path"])):
            w.writerow(row)

    missing = sorted(seen_tools - inventory)
    not_seen = sorted(inventory - seen_tools)

    def write_list(path, rows, header):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([header])
            for r in rows:
                w.writerow([r])

    write_list(os.path.join(args.outdir,"diff_missing_in_inventory.csv"), missing,
               "Tool (found in GitHub, NOT in tools.csv)")
    write_list(os.path.join(args.outdir,"diff_not_seen_in_github.csv"), not_seen,
               "Tool (in tools.csv, NOT detected in GitHub)")

    print("\n".join([
        f"Inventory tools: {len(inventory)}",
        f"Discovered in GitHub: {len(seen_tools)}",
        f"Missing in inventory: {len(missing)}",
        f"Not seen in GitHub (possibly planned/local): {len(not_seen)}",
        "", "Open:",
        f"  - {disc_csv}",
        f"  - {os.path.join(args.outdir,'diff_missing_in_inventory.csv')}",
        f"  - {os.path.join(args.outdir,'diff_not_seen_in_github.csv')}",
    ]))

if __name__ == "__main__":
    main()
