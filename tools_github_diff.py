#!/usr/bin/env python3
import os, csv, base64, re, argparse, requests

# Scan a wide set of text-ish files (<= 250 KB)
TEXTY = (
    r"\.(json|jsonc|toml|lock|yaml|yml|md|txt|ini|cfg|conf|properties|"
    r"sh|bash|zsh|ps1|py|rb|pl|php|js|ts|mjs|cjs|go|rs|java|kt|scala|rb|"
    r"sol|vy|move|cairo|ligo)$"
)
SPECIAL = r"(?:^|/)(Dockerfile|Makefile|\.tool-versions|\.env|\.env\.example|\.github/workflows/[^/]+\.ya?ml)$"
PAT = re.compile(rf"(?:{TEXTY})|{SPECIAL}", re.I)

MAX_BYTES = 250_000

DETECTORS = [
    # Core smart-contract toolchain
    (r"\bslither\b", "Slither"),
    (r"\bechidna\b|ghcr\.io/crytic/echidna", "Echidna"),
    (r"\bmythril\b", "Mythril"),
    (r"\bmanticore\b", "Manticore"),
    (r"\bmedusa\b", "Medusa"),
    (r"\bhalmos\b", "Halmos"),
    (r"\bcertora[-_ ]?cli\b|\bcertora-cli\b", "certora-cli"),
    (r"\bsolc-select\b", "solc-select"),
    (r"\bsolc\b", "solc"),
    (r"\bforge\b|\bcast\b|\banvil\b", "Foundry (forge/cast/anvil)"),
    (r"\bhardhat\b", "Hardhat"),
    (r"\btruffle\b", "Truffle"),
    (r"\bbrownie\b", "Brownie"),
    (r"\bape(\W|$)|\bApeWorx\b", "ApeWorx (Ape)"),
    (r"\bsolhint\b", "Solhint"),
    (r"\bsolidity-coverage\b", "Solidity Coverage"),
    (r"\bganache\b", "Ganache"),
    (r"\bopenzeppelin[- ]contracts\b", "OpenZeppelin Contracts"),
    (r"\bsafe[- ]?cli\b", "Safe CLI"),
    # Security scanners & supply-chain
    (r"\bsemgrep\b", "Semgrep"),
    (r"\btrivy\b", "Trivy"),
    (r"\bosv[- ]?scanner\b|\bosv-scanner\b", "OSV-Scanner"),
    (r"\bsnyk\b", "Snyk"),
    (r"\bbandit\b", "Bandit"),
    (r"\bsafety\b", "Safety"),
    (r"\bpip[- ]?audit\b", "pip-audit"),
    (r"\bnpm audit\b|\bpnpm audit\b|\byarn audit\b", "npm/pnpm/yarn audit"),
    (r"\bcargo[- ]?audit\b", "cargo-audit"),
    (r"\bgitleaks\b", "gitleaks"),
    (r"\btrufflehog\b", "trufflehog"),
    # Other chains & devkits
    (r"\bgoal\b", "Algorand goal"),
    (r"\bpyteal\b", "PyTeal"),
    (r"\baptos[- ]?cli\b|\baptos-cli\b|\baptos\b", "aptos-cli"),
    (r"\bcosmos[- ]?sdk\b", "Cosmos SDK"),
    (r"\bgaiad\b", "Gaiad"),
    (r"\bhermes\b", "Hermes (IBC)"),
    (r"\bignite\b", "Ignite CLI"),
    (r"\banchor\b", "Anchor"),
    (r"\bspl[- ]?token\b|\bspl-token\b", "SPL Token CLI"),
    (r"\bsolana[- ]?cli\b|\bsolana program\b", "Solana CLI"),
    (r"\bseahorse\b", "Seahorse"),
    (r"\bsolang\b", "Solang"),
    (r"\bscarb\b|\bcairo\b", "Cairo 1 / scarb"),
    (r"\bkatana\b", "katana (dojo)"),
    (r"\bstarknet[- ]?foundry\b|\bsnf\b", "starknet Foundry"),
    (r"\bcargo[- ]?contract\b", "cargo-contract"),
    (r"\bink!\b|\bink\b", "ink!"),
    (r"\bpolkadot\b", "polkadot"),
    (r"\bsui[- ]?cli\b|\bsui\b", "sui-cli"),
    (r"\bnear[- ]?cli\b", "near-cli"),
    (r"\bSmartPy\b|\bsmartpy\b", "SmartPy"),
    (r"\bligo\b", "LIGO"),
]


def _headers():
    t = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    h = {"Accept": "application/vnd.github+json", "User-Agent": "armor-ai-diff"}
    if t:
        h["Authorization"] = f"Bearer {t}"
    return h


def _get(url, **kw):
    return requests.get(url, headers=_headers(), timeout=30, **kw)


def list_repos_for(owner):
    out = []
    for kind in ("orgs", "users"):
        page = 1
        while True:
            r = _get(
                f"https://api.github.com/{kind}/{owner}/repos",
                params={
                    "per_page": 100,
                    "page": page,
                    "type": "all",
                    "sort": "updated",
                },
            )
            if r.status_code == 404:
                break
            r.raise_for_status()
            batch = r.json()
            if not batch:
                break
            out += batch
            if len(batch) < 100:
                break
            page += 1
        if out:
            return out
    return out


def default_branch_sha(owner, repo, default_branch):
    r = _get(f"https://api.github.com/repos/{owner}/{repo}/branches/{default_branch}")
    r.raise_for_status()
    return r.json()["commit"]["sha"]


def walk_tree(owner, repo, sha):
    r = _get(f"https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}?recursive=1")
    r.raise_for_status()
    t = r.json()
    return [e for e in t.get("tree", []) if e.get("type") == "blob"]


def read_blob(owner, repo, path, ref):
    r = _get(
        f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
        params={"ref": ref},
    )
    if r.status_code == 404:
        return ""
    r.raise_for_status()
    j = r.json()
    if isinstance(j, dict) and j.get("encoding") == "base64":
        return base64.b64decode(j["content"]).decode("utf-8", "ignore")
    return ""


def detect(text):
    out = set()
    for rx, name in DETECTORS:
        if re.search(rx, text, flags=re.I):
            out.add(name)
    return out


def load_inventory(path):
    tools = set()
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            t = (row.get("Tool") or "").strip()
            if t:
                tools.add(t)
    return tools


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--orgs", required=True, help="comma-separated orgs/users")
    ap.add_argument("--outdir", default="artifacts")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    inventory = load_inventory(args.inventory)
    discovered = []
    seen = set()

    for who in [x.strip() for x in args.orgs.split(",") if x.strip()]:
        repos = list_repos_for(who)
        for r in repos:
            owner = r["owner"]["login"]
            repo = r["name"]
            ref = r["default_branch"]
            try:
                sha = default_branch_sha(owner, repo, ref)
                blobs = walk_tree(owner, repo, sha)
            except requests.HTTPError:
                continue
            # only scan text-ish files and cap size to keep calls reasonable
            cand = [
                b
                for b in blobs
                if (
                    PAT.search(b["path"])
                    or b.get("path", "").endswith((".sol", ".vy", ".move", ".cairo"))
                )
                and b.get("size", 0) <= MAX_BYTES
            ]
            for b in cand:
                txt = read_blob(owner, repo, b["path"], ref)
                if not txt:
                    continue
                found = detect(txt)
                for name in found:
                    discovered.append(
                        {"Tool": name, "Repo": f"{owner}/{repo}", "Path": b["path"]}
                    )
                    seen.add(name)

    disc_csv = os.path.join(args.outdir, "github_tools_detected.csv")
    with open(disc_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["Tool", "Repo", "Path"])
        w.writeheader()
        for row in sorted(discovered, key=lambda x: (x["Tool"], x["Repo"], x["Path"])):
            w.writerow(row)

    missing = sorted(seen - inventory)
    not_seen = sorted(inventory - seen)

    def emit(path, rows, header):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([header])
            [w.writerow([r]) for r in rows]

    emit(
        os.path.join(args.outdir, "diff_missing_in_inventory.csv"),
        missing,
        "Tool (found in GitHub, NOT in tools.csv)",
    )
    emit(
        os.path.join(args.outdir, "diff_not_seen_in_github.csv"),
        not_seen,
        "Tool (in tools.csv, NOT detected in GitHub)",
    )

    print(f"Inventory tools: {len(inventory)}")
    print(f"Discovered in GitHub: {len(seen)}")
    print(f"Missing in inventory: {len(missing)}")
    print(f"Not seen in GitHub (possibly planned/local): {len(not_seen)}")
    print(
        "\nOpen:\n  -",
        disc_csv,
        "\n  -",
        os.path.join(args.outdir, "diff_missing_in_inventory.csv"),
        "\n  -",
        os.path.join(args.outdir, "diff_not_seen_in_github.csv"),
    )


if __name__ == "__main__":
    main()
