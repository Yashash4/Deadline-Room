"""IdP adapter for the two-key release signers: authenticate the human signers of
the segregation-of-duties gate against a real identity provider (OIDC/SAML), so the
keys are REAL authenticated identities rather than fixed role labels, behind a clean
interface with the in-process stub as the default.

This is the RIGHT edge of the human release. The two-key gate
(`warden.release_gate.TwoKeyReleaseGate`) requires two DISTINCT roles
(`general_counsel` and `head_of_ir`) to both sign before the Warden admits
HUMAN_RELEASED. In the hackathon those signers were honest `[STUB]` role labels:
the run named "gc" and "lena" as fixed actors. Production authenticates each signer
against the organization's IdP (Okta, Entra ID, Ping, any OIDC/SAML provider), so
the recorded sign-off names a verified human identity (subject, email, the issuer
that vouched for them), not just a role string.

THE ABSOLUTE CONSTRAINT THIS MODULE HONORS. The `release_signoff` event is INSIDE
the hashed run-log, and the four sealed run-log shas are byte-frozen. So the DEFAULT
path (the stub) must produce a release_signoff payload byte-identical to today: the
stub authenticates to NOTHING and contributes NO extra field, so the seven-key
payload (`correlation_id, role, actor, ts, released, have_roles, missing_roles,
reason`) is unchanged and the sealed shas do not move. The authenticated identity is
bound into the event ONLY when a real IdP is explicitly configured (a non-default
provider), which is a DIFFERENT run that was never one of the four sealed captures.

WHY A PROVIDER. An IdP never hands the floor a fixed actor string; it
authenticates a session and returns a verified identity (an OIDC ID token's
`sub`/`email`, a SAML assertion's NameID/attributes). Modeling the signer identity
as a provider with `authenticate(role) -> AuthenticatedIdentity | None` is the
faithful seam: the stub and a live OIDC provider are interchangeable through it, and
the binding into the run-log is a single, additive, gated change.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticatedIdentity:
    """A signer's verified identity, as an IdP returns it. Bound into the
    release_signoff event ONLY when a real IdP is configured.

      * `subject` : the IdP's stable subject id (OIDC `sub` / SAML NameID).
      * `email`   : the signer's verified email (OIDC `email` claim / SAML attr).
      * `issuer`  : the IdP that vouched (OIDC `iss` / SAML Issuer), so an examiner
        can see WHO authenticated the signer, not just the role label.
      * `method`  : "oidc" or "saml", the protocol the assertion came over."""
    subject: str
    email: str
    issuer: str
    method: str

    def as_event_field(self) -> dict:
        """The deterministic, sorted-key dict bound into the release_signoff event.
        Plain JSON-serializable scalars only, so the run-log canonicalization
        (`sort_keys=True`) produces stable bytes."""
        return {
            "subject": self.subject,
            "email": self.email,
            "issuer": self.issuer,
            "method": self.method,
        }


class IdpProvider:
    """The IdP seam: authenticate one release signer by role and return their
    verified identity, or None when no real IdP is configured.

      * `authenticate(role) -> AuthenticatedIdentity | None` : verify the human
        holding `role` against the IdP and return their identity. Returns None on
        the stub (no IdP), which is what keeps the default release_signoff event
        byte-identical: a None identity contributes NO field to the event.

    A provider that returns a non-None identity is, by definition, a configured real
    IdP, and binding that identity changes the run-log for THAT run only (never one
    of the four sealed captures)."""

    def authenticate(self, role: str) -> AuthenticatedIdentity | None:
        raise NotImplementedError

    @property
    def is_configured(self) -> bool:
        """True iff this provider authenticates against a real IdP (and so binds an
        identity into the signoff). The stub is NOT configured, so the default run is
        byte-identical."""
        return True


class StubIdpProvider(IdpProvider):
    """The DEFAULT provider: NO real IdP. `authenticate` returns None for every
    role, so the signers stay the fixed role labels the gate already uses and the
    release_signoff event is byte-identical to today. This is the hackathon's honest
    `[STUB]` behavior, now behind the seam, so CI runs offline and the four sealed
    shas do not move."""

    def authenticate(self, role: str) -> AuthenticatedIdentity | None:
        return None

    @property
    def is_configured(self) -> bool:
        return False


class StaticIdpProvider(IdpProvider):
    """A configured provider backed by an in-memory directory, for tests and to
    PROVE the seam: it maps each role to a verified `AuthenticatedIdentity` exactly
    as a real OIDC/SAML provider would after authenticating the session, but without
    a network call. A test uses this to assert that WHEN an IdP is configured, the
    authenticated identity binds into the release_signoff event (a non-default run);
    a real provider returns the same shape from a live assertion."""

    def __init__(self, identities: dict[str, AuthenticatedIdentity]) -> None:
        self._identities = dict(identities)

    def authenticate(self, role: str) -> AuthenticatedIdentity | None:
        return self._identities.get(role)


@dataclass
class OidcIdpProvider(IdpProvider):
    """Production signer authentication via OpenID Connect. SHIPPED AS A CLEAN
    INTERFACE, not a live call: the IdP round-trip is left to a deployer to wire to
    its OIDC provider, because a reproducible offline build must not depend on a live
    IdP. This is the seam, documented, that a deployment fills in.

    Wiring (Okta, Microsoft Entra ID, Auth0, Ping, any OIDC provider):

      * The signer authenticates through the provider's authorization-code flow at
        `issuer`/`discovery_url`; the release UI receives an ID token.
      * `authenticate(role)` validates the ID token signature against the provider's
        JWKS, checks `aud`/`exp`/`iss`, confirms the authenticated subject is
        authorized to hold `role` (a directory/group check), and returns an
        `AuthenticatedIdentity` from the `sub`, `email`, and `iss` claims, method
        "oidc".

    The returned identity is the same shape `StaticIdpProvider` returns, so the
    binding into the release_signoff event is identical; only the authentication is
    real."""

    issuer: str
    client_id: str
    discovery_url: str = ""

    def authenticate(self, role: str) -> AuthenticatedIdentity | None:
        raise NotImplementedError(
            "OidcIdpProvider.authenticate is the production seam: run the OIDC "
            f"authorization-code flow against issuer {self.issuer!r} for client "
            f"{self.client_id!r}, validate the ID token against the JWKS, confirm the "
            f"subject is authorized for role {role!r}, and return an "
            "AuthenticatedIdentity built from the sub/email/iss claims (method "
            "'oidc').")


@dataclass
class SamlIdpProvider(IdpProvider):
    """Production signer authentication via SAML 2.0. SHIPPED AS A CLEAN INTERFACE,
    not a live call, for the same reason as `OidcIdpProvider`: an offline build
    cannot depend on a live IdP.

    Wiring (ADFS, Shibboleth, any SAML 2.0 IdP):

      * The signer authenticates through the IdP's SSO endpoint; the release UI
        receives a signed SAML assertion (an `AuthnResponse`).
      * `authenticate(role)` validates the assertion signature against the IdP's
        certificate, checks the `Conditions`/`Audience`/`NotOnOrAfter`, confirms the
        NameID is authorized for `role`, and returns an `AuthenticatedIdentity` from
        the NameID (subject), the email attribute, and the Issuer, method "saml".

    The returned identity is the same shape, so the binding is identical."""

    entity_id: str
    sso_url: str
    idp_cert: str = ""

    def authenticate(self, role: str) -> AuthenticatedIdentity | None:
        raise NotImplementedError(
            "SamlIdpProvider.authenticate is the production seam: validate the signed "
            f"SAML assertion against the IdP certificate for entity {self.entity_id!r}, "
            f"confirm the NameID is authorized for role {role!r}, and return an "
            "AuthenticatedIdentity built from the NameID/email/Issuer (method 'saml').")


def signoff_identity_field(provider: IdpProvider, role: str) -> dict:
    """The additive payload fragment merged into a release_signoff event for one
    signer. EMPTY ({}) for the stub / any provider that returns None, so the default
    event is byte-identical and the four sealed shas do not move. When a real IdP is
    configured and authenticates the signer, this returns
    `{"authenticated_identity": {...}}`, binding the verified identity into the
    hashed run-log for THAT non-default run only.

    This is the single point where the gating rule lives: no IdP -> no field ->
    byte-identical; configured IdP -> bound identity. The caller (`_two_key_release`)
    merges this fragment into the event payload, so the default path is provably
    unchanged."""
    if not provider.is_configured:
        return {}
    identity = provider.authenticate(role)
    if identity is None:
        return {}
    return {"authenticated_identity": identity.as_event_field()}


def idp_provider() -> IdpProvider:
    """The IdP the release signers authenticate against. DEFAULT: the stub (no IdP),
    so the signers stay fixed role labels and the release_signoff event is
    byte-identical to today. A deployment returns an `OidcIdpProvider`/
    `SamlIdpProvider` here instead, and each signer's verified identity binds into
    the signoff."""
    return StubIdpProvider()
