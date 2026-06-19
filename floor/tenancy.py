"""Multi-tenant control plane: tenant-scoped data, custody, and catalog overrides.

A single sealed-and-signed Warden run is the source of truth for ONE incident. A
standing operations center, though, serves an ORGANIZATION with structure: a
group with subsidiaries and legal entities, each with its own incidents and its
own regulator exposure, and at production scale several customer organizations
(tenants) sharing one deployment. Two questions follow that a flat folder of
runs cannot answer:

  1. SEGMENTATION (per-entity). The board wants a roll-up segmented by regulated
     entity, AND a per-subsidiary signed sub-attestation a subsidiary GC can hand
     to its own regulator WITHOUT exposing the rest of the group. That is the
     two-level signed tree in floor/portfolio.py: a per-entity Merkle sub-root,
     each signed, combining into the group root.

  2. ISOLATION (per-tenant). Each tenant's runs live under its own data_dir, are
     sealed and signed independently, and never leak into another tenant's
     attestation. A tenant points custody at its OWN signing key through the E2.5
     SigningProvider seam (warden/custody.py), and may override the regime catalog
     (a tenant in a different jurisdiction watches a different deadline set).

WHERE THIS STATE LIVES: OUTSIDE the sealed spine. The four per-run sealed
run-log shas and their byte-identical replay are frozen and read-only. Tenant
identity, the data-dir namespacing, the per-tenant key, the catalog override, and
the run-to-entity mapping are all configuration that sits BESIDE the sealed
captures, never inside the hashed JSONL. Segmentation is therefore a pure
GROUPING over read-only per-run bytes; it seals nothing new and edits no sealed
byte. This is the same discipline the intake queue (web/data/intake.json) and the
fleet rollup already follow: declarative state outside the signed object.

THE RUN-TO-ENTITY MAP. The regulated entity is a fact-record field (the filer),
posted into the room but NOT folded into the sealed run-log bytes, so it lives
outside the spine like the rest of the tenant state. A run's entity is resolved
in two deterministic steps, most-specific first: an in-band `regulated_entity`
on a run-log payload wins when present (a future capture that carries it needs no
external map), else the declarative tenant entity map (web/data/entities.json or a
tenant override) assigns it. A run with neither resolves to UNASSIGNED_ENTITY, a
named bucket, never silently dropped, so the segmentation total always equals the
attested set.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from warden.custody import (
    LocalKeyProvider,
    SigningProvider,
    warden_signing_provider,
)

# The bucket a run lands in when no entity can be resolved for it (neither an
# in-band field nor a declarative map entry). Named, never empty, so a run is
# always accounted for in exactly one segment and the per-entity counts sum to the
# attested total. A board that shows a non-zero UNASSIGNED bucket is telling the
# operator "these runs need an entity assigned", which is honest, not a silent loss.
UNASSIGNED_ENTITY = "(unassigned)"

# The declarative run-to-entity map shipped beside the sealed captures, the same
# place the intake queue's pending set lives. It maps a run-log file name to the
# regulated entity that filed it, for captures that do not carry the field in-band.
DEFAULT_ENTITY_MAP_NAME = "entities.json"


def load_entity_map(data_dir: str | Path,
                    name: str = DEFAULT_ENTITY_MAP_NAME) -> dict[str, str]:
    """Load the declarative run-to-entity map from `data_dir/<name>`.

    The file is a small JSON object `{"runs": {"<run-log name>": "<entity>", ...}}`,
    declarative tenant configuration OUTSIDE the sealed spine (it seals nothing and
    edits no run-log byte). A missing or malformed file yields an EMPTY map rather
    than raising, so segmentation still runs (every run then resolves in-band or
    falls to UNASSIGNED_ENTITY); a present file is read read-only. Keys that are not
    string->string pairs are skipped so a sparse or partly-edited map never crashes
    the board."""
    path = Path(data_dir) / name
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}
    runs = doc.get("runs", {}) if isinstance(doc, dict) else {}
    if not isinstance(runs, dict):
        return {}
    return {
        str(k): str(v)
        for k, v in runs.items()
        if isinstance(k, str) and isinstance(v, str) and v
    }


@dataclass(frozen=True)
class TenantConfig:
    """One tenant's configuration in the multi-tenant control plane.

    A tenant is a customer organization sharing the deployment. Its state is held
    here, entirely OUTSIDE the sealed/signed spine:

      * `tenant_id`      : the stable identifier that namespaces everything below.
      * `data_dir`       : the directory the tenant's sealed runs live under. Each
                           tenant's corpus is a distinct directory, so one tenant's
                           runs are never discovered while attesting another's; that
                           directory isolation is what the isolation tests assert.
      * `entity_map`     : the declarative run-to-entity map for this tenant's
                           corpus (run-log name -> regulated entity), used when a
                           run does not carry the entity in-band.
      * `catalog_override`: an optional path to a tenant-specific regime catalog
                           (a tenant in another jurisdiction watches a different
                           deadline set). None means the shipped default catalog.
      * `signing_provider`: the custody seam (warden/custody.SigningProvider) that
                           signs THIS tenant's attestations. Defaults to the
                           committed demo key (byte-identical to today); a
                           deployment points each tenant at its own KMS/HSM key, so
                           one tenant can never sign as another.

    The object is frozen: a tenant config is read configuration, not mutable state
    a request can edit mid-flight."""
    tenant_id: str
    data_dir: Path
    entity_map: dict[str, str] = field(default_factory=dict)
    catalog_override: Path | None = None
    signing_provider: SigningProvider | None = None

    def provider(self) -> SigningProvider:
        """The signing provider for this tenant: its own key if one was wired,
        else the committed demo Warden provider (byte-identical to today). Routing
        every tenant through the SAME SigningProvider interface is what lets a
        deployment swap in a per-tenant KMS/HSM key without touching a call site."""
        return self.signing_provider or warden_signing_provider()


def tenant_from_dir(tenant_id: str, data_dir: str | Path,
                    *, catalog_override: str | Path | None = None,
                    signing_provider: SigningProvider | None = None,
                    entity_map_name: str = DEFAULT_ENTITY_MAP_NAME) -> TenantConfig:
    """Build a `TenantConfig` for `tenant_id` over `data_dir`, loading the tenant's
    declarative entity map from that directory.

    The tenant id namespaces the data dir (each tenant a distinct directory), the
    entity map is read read-only from beside the tenant's sealed captures, and the
    optional catalog override and signing provider are carried through. Pure
    construction: it reads the map file and holds paths; it seals nothing and
    mutates no sealed byte."""
    data_path = Path(data_dir)
    override = Path(catalog_override) if catalog_override is not None else None
    return TenantConfig(
        tenant_id=tenant_id,
        data_dir=data_path,
        entity_map=load_entity_map(data_path, entity_map_name),
        catalog_override=override,
        signing_provider=signing_provider,
    )


def demo_tenants(data_dir: str | Path) -> list[TenantConfig]:
    """The committed demo tenant set: a single default tenant over `data_dir`.

    The shipped corpus is one organization's sealed runs, so the demo control plane
    has one tenant whose entity map (web/data/entities.json) segments that
    organization into its subsidiaries. A real deployment registers N tenants, each
    over its own data dir with its own key; the shape here is that registry with one
    entry. Each tenant signs with the committed demo provider by default, which keeps
    the build keyless-runnable and byte-identical; a deployment passes a
    `MockKmsProvider`/`KmsProvider`/`Pkcs11Provider` per tenant instead."""
    return [tenant_from_dir("default", data_dir)]


def isolated_demo_provider(seed_label: str) -> SigningProvider:
    """A distinct in-process signing provider for a tenant in tests/demos, derived
    deterministically from a label so two tenants get two different keys.

    Used to PROVE isolation: tenant A signs with one key, tenant B with another, and
    a sub-attestation signed by A never verifies under B's key. The key is generated
    from a sha256 of the label (a stable 32-byte Ed25519 seed), so the same label
    always yields the same key, keeping tests deterministic without committing a
    second demo seed. A real deployment uses a KMS/HSM provider here; this is the
    in-process stand-in the seam is shaped for."""
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = hashlib.sha256(f"deadline-room/tenant/{seed_label}".encode("utf-8")).digest()
    return LocalKeyProvider(Ed25519PrivateKey.from_private_bytes(seed))
