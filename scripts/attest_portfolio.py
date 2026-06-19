"""One-command signed portfolio attestation over the whole fleet of sealed runs.

A per-run signature proves a single run-log was not tampered with. This script
answers the FLEET-level question: are ALL the sealed runs intact, and was no run
silently dropped from the record? It discovers every `run-*.jsonl` with a sibling
per-run signature under web/data/, re-verifies each one, folds a Merkle root over
the SORTED chain heads of the runs that pass, signs that root (under a DISTINCT
portfolio label so it is never confused with a per-run receipt), and writes the
signed portfolio manifest to its OWN sidecar.

  py scripts/attest_portfolio.py                       (build + write the manifest)
  py scripts/attest_portfolio.py --verify <manifest>   (re-verify a manifest)

Build mode RE-DERIVES the root from the sealed runs and writes
web/data/portfolio-attestation.json: the canonical manifest plus the detached
portfolio signature. Verify mode reads a manifest, RE-DISCOVERS the sealed runs
on disk, recomputes the root, checks the portfolio signature, and DETECTS a
dropped run, a run named in the manifest but missing on disk, or a run on disk
but absent from the manifest. It prints the root, the run count, the per-run
chain heads, VALID or INVALID, and the honest demo-key caveat every time: the
signing mechanism is real, the key's secrecy is not production-grade.

This script is keyless to RUN as a verifier (it needs only the committed public
key) and read-only over the sealed captures: it writes only its own portfolio
sidecar and never a run log or a per-run signature.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.portfolio import (  # noqa: E402
    PortfolioAttestation,
    PortfolioInsights,
    PortfolioSla,
    attest_portfolio,
    insights_dict,
    insights_dict_digest,
    load_portfolio,
    manifest_digest,
    sla_dict,
    sla_dict_digest,
)
from warden.portfolio_signing import (  # noqa: E402
    sign_portfolio,
    verify_portfolio,
)
from warden.signing import DEMO_KEY_CAVEAT  # noqa: E402

DATA_DIR = REPO_ROOT / "web" / "data"
DEFAULT_MANIFEST = DATA_DIR / "portfolio-attestation.json"


def _print_runs(attestation: PortfolioAttestation) -> None:
    print(f"Portfolio root : {attestation.root}")
    print(f"Run count      : {attestation.run_count}")
    print("Attested runs (each folded into the Merkle root by its chain head):")
    name_w = max((len(r.name) for r in attestation.attested), default=4)
    for run in attestation.attested:
        print(f"  {run.name.ljust(name_w)}  head {run.chain_head}")
    if attestation.flagged:
        print("Flagged runs (excluded: per-run signature did NOT verify):")
        for run in attestation.flagged:
            print(f"  {run.name}: {run.flag}")
    print()


def _print_insights(insights: PortfolioInsights) -> None:
    """Print the cross-incident findings folded from the sealed logs (E6.3).

    Pure counts and groupings, no narrative: repeat offenders (any attacker
    spanning two or more incidents), field-level contradiction-veto recurrence,
    suppress dispositions per regime, and incidents grouped by regulated entity.
    A finding with no data prints `(none)` rather than nothing, so the reader can
    tell the fold ran and found zero, not that it was skipped."""
    print("Cross-incident findings (folded from the sealed logs, zero LLM):")
    if insights.repeat_offenders:
        print("  Repeat offenders (same attacker across >= 2 incidents):")
        for attacker, incidents in insights.repeat_offenders.items():
            print(f"    {attacker}: {len(incidents)} incidents "
                  f"({', '.join(incidents)})")
    else:
        print("  Repeat offenders: (none on the attested set)")
    if insights.veto_field_recurrence:
        print("  Contradiction-veto recurrence by disputed field:")
        for field, count in insights.veto_field_recurrence.items():
            print(f"    {field}: vetoed {count} time(s)")
    else:
        print("  Contradiction-veto recurrence: (none)")
    if insights.suppress_by_regime:
        print("  Suppress dispositions by regime:")
        for regime, count in insights.suppress_by_regime.items():
            print(f"    {regime}: {count}")
    else:
        print("  Suppress dispositions by regime: (none)")
    if insights.incidents_by_entity:
        print("  Incidents by regulated entity:")
        for entity, incidents in insights.incidents_by_entity.items():
            print(f"    {entity}: {', '.join(incidents)}")
    else:
        print("  Incidents by regulated entity: (none)")
    print()


def _print_sla(sla: PortfolioSla) -> None:
    """Print the fleet SLA / throughput roll-up folded from the sealed runs (E6.4).

    The standing-operations-center view: per-run filings and tightest margin, then
    the fleet aggregates a CISO is judged on (worst-case and median statutory
    margin, near-breach and breach counts, the nearest deadline across the whole
    fleet, and the aggregated throughput). Every number is a pure read of the
    sealed clock and protocol entries, never a now() or an estimate."""
    print("Fleet SLA / throughput roll-up (folded from the sealed clocks, zero LLM):")
    name_w = max((len(r.name) for r in sla.per_run), default=4)
    for run in sla.per_run:
        min_margin = ("n/a" if run.min_margin_hours is None
                      else f"{run.min_margin_hours:.2f}h")
        tp = run.throughput
        print(f"  {run.name.ljust(name_w)}  filings {run.filings_landed} "
              f"min-margin {min_margin}  breaches {run.breaches}  "
              f"drafted {tp['drafted']} released {tp['released']} "
              f"suppressed {tp['suppressed']} diff-conflicts {tp['diff_conflicts']}")
    worst = ("n/a" if sla.worst_margin_hours is None
             else f"{sla.worst_margin_hours:.2f}h")
    median = ("n/a" if sla.median_margin_hours is None
              else f"{sla.median_margin_hours:.2f}h")
    print("  ----")
    print(f"  Filings across the fleet     : {sla.total_filings}")
    print(f"  Worst-case statutory margin  : {worst}"
          + (f" (run {sla.worst_margin_run}, clock {sla.worst_margin_clock!r})"
             if sla.worst_margin_hours is not None else ""))
    print(f"  Median statutory margin      : {median}")
    print(f"  Filings within {sla.near_breach_hours:.0f}h of breach : "
          f"{sla.near_breach_count}")
    print(f"  Breaches across the fleet    : {sla.total_breaches}")
    print(f"  Ever breached                : {'YES' if sla.ever_breached else 'no'}")
    print(f"  Nearest deadline (fleet)     : "
          f"{sla.nearest_deadline_utc or '(none)'}")
    print(f"  Throughput drafted/released/suppressed : "
          f"{sla.throughput_drafted}/{sla.throughput_released}/"
          f"{sla.throughput_suppressed}")
    print()


def build(data_dir: Path, out_path: Path) -> int:
    """Build the signed portfolio manifest and write it to its sidecar."""
    print("=" * 78)
    print("PORTFOLIO ATTESTATION: one signed root over the whole fleet of runs")
    print("=" * 78)
    runs = load_portfolio(data_dir)
    attestation = attest_portfolio(runs)
    _print_runs(attestation)
    _print_insights(attestation.insights)
    _print_sla(attestation.sla)

    signature = sign_portfolio(
        attestation.root, attestation.run_count, attestation.manifest_sha256,
        attestation.insights_sha256, attestation.sla_sha256)
    document = {
        "manifest": attestation.manifest,
        "manifest_sha256": attestation.manifest_sha256,
        "signature": signature,
    }
    out_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    print(f"Wrote signed portfolio manifest to {out_path}")
    print(f"Signer fp      : {signature['pubkey_fingerprint']}")
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 78)
    return 0


def _recompute_from_disk(data_dir: Path) -> PortfolioAttestation:
    """Re-discover and re-fold the sealed runs straight off disk."""
    return attest_portfolio(load_portfolio(data_dir))


def verify(manifest_path: Path, data_dir: Path) -> int:
    """Re-verify a portfolio manifest against the sealed runs on disk.

    Recomputes the Merkle root from disk, checks the portfolio signature, and
    cross-checks the manifest's run set against the runs actually present so a
    dropped run (in the manifest, gone from disk) or an extra run (on disk, absent
    from the manifest) is detected and named."""
    print("=" * 78)
    print("PORTFOLIO VERIFY: does the signed root still cover every sealed run?")
    print("=" * 78)
    if not manifest_path.exists():
        print(f"attest_portfolio: no manifest at {manifest_path}",
              file=sys.stderr)
        return 2
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    stored_manifest = document.get("manifest", {}) or {}
    signature = document.get("signature", {}) or {}

    recomputed = _recompute_from_disk(data_dir)
    stored_runs = {r["name"]: r for r in stored_manifest.get("runs", [])}
    disk_runs = {r.name: r for r in recomputed.attested}
    stored_insights = stored_manifest.get("insights", {}) or {}
    stored_sla = stored_manifest.get("sla", {}) or {}

    print(f"Manifest       : {manifest_path}")
    print(f"Stored root    : {stored_manifest.get('portfolio_root', '(absent)')}")
    print(f"Recomputed root: {recomputed.root}")
    print(f"Stored count   : {stored_manifest.get('run_count', '(absent)')}")
    print(f"Disk count     : {recomputed.run_count}")
    print("Per-run chain heads on disk:")
    name_w = max((len(n) for n in disk_runs), default=4)
    for name in sorted(disk_runs):
        print(f"  {name.ljust(name_w)}  head {disk_runs[name].chain_head}")
    print()
    _print_insights(recomputed.insights)
    _print_sla(recomputed.sla)

    failures: list[str] = []

    dropped = sorted(set(stored_runs) - set(disk_runs))
    extra = sorted(set(disk_runs) - set(stored_runs))
    for name in dropped:
        failures.append(f"DROPPED RUN: {name} is in the manifest but missing on disk")
    for name in extra:
        failures.append(f"UNATTESTED RUN: {name} is on disk but absent from the manifest")

    for name in sorted(set(stored_runs) & set(disk_runs)):
        if stored_runs[name].get("chain_head") != disk_runs[name].chain_head:
            failures.append(
                f"TAMPERED RUN: {name} chain head moved since the manifest was signed")

    # The root the signature covers must equal the root re-derived from disk.
    stored_root = stored_manifest.get("portfolio_root", "")
    if recomputed.root != stored_root:
        failures.append(
            "ROOT MISMATCH: the root re-derived from disk does not match the "
            "manifest root")

    # The cross-incident findings re-derived from disk must match the stored
    # findings (an edited finding no longer matches the sealed logs).
    disk_insights = insights_dict(recomputed.insights)
    if disk_insights != stored_insights:
        failures.append(
            "INSIGHTS MISMATCH: the cross-incident findings in the manifest do "
            "not re-derive from the sealed logs")

    # The fleet SLA / throughput rollup re-derived from disk must match the stored
    # rollup (an edited margin, breach count, or throughput number no longer
    # re-derives from the sealed clock and protocol entries).
    disk_sla = sla_dict(recomputed.sla)
    if disk_sla != stored_sla:
        failures.append(
            "SLA MISMATCH: the fleet SLA / throughput rollup in the manifest does "
            "not re-derive from the sealed logs")

    # The manifest the signature commits to must canonicalize to the stored digest.
    recomputed_manifest_digest = manifest_digest(stored_manifest)
    if recomputed_manifest_digest != document.get("manifest_sha256"):
        failures.append("MANIFEST DIGEST MISMATCH: the stored manifest was edited")

    # The portfolio signature must verify over the STORED root, count, the digest
    # of the STORED findings, AND the digest of the STORED SLA rollup (so editing a
    # finding or a rollup number breaks the signature directly, not only the
    # manifest digest cross-check).
    stored_insights_digest = insights_dict_digest(stored_insights)
    stored_sla_digest = sla_dict_digest(stored_sla)
    sig_ok = verify_portfolio(
        stored_manifest.get("portfolio_root", ""),
        stored_manifest.get("run_count", -1),
        stored_insights_digest,
        stored_sla_digest,
        signature)
    if not sig_ok:
        failures.append("SIGNATURE INVALID: the portfolio signature does not verify")

    print(f"Signer fp      : {signature.get('pubkey_fingerprint', '(absent)')}")
    print()
    if failures:
        print("INVALID. The portfolio no longer covers the fleet intact:")
        for item in failures:
            print(f"  - {item}")
        print(f"Note: {DEMO_KEY_CAVEAT}")
        print("=" * 78)
        return 1

    print("VALID. The signed Merkle root re-derives from every sealed run on disk,")
    print("the run set matches exactly (no run dropped, none unattested), the")
    print("cross-incident findings and the fleet SLA / throughput rollup re-derive")
    print("from the sealed logs, and the portfolio signature verifies under the")
    print("committed public key.")
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 78)
    return 0


def main(argv: list[str]) -> int:
    if "--verify" in argv:
        idx = argv.index("--verify")
        rest = [a for a in argv[idx + 1:] if not a.startswith("--")]
        manifest_path = (Path(rest[0]).resolve() if rest else DEFAULT_MANIFEST)
        return verify(manifest_path, DATA_DIR)
    return build(DATA_DIR, DEFAULT_MANIFEST)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
