//! An attribute: one thing a rule may read off the record or the attempt.

use authorize::{Action, Attempt};
use context::IdentityFacts;
use std::fmt;
use xcore::Assurance;

/// One thing a rule may read.
///
/// The identity attributes are the accountable identity's — the transport
/// one — because this is a transport-layer policy (ADR-0019 clause 6).
/// Evidence is the exception: a claim is looked for on the transport
/// identity first and the message identity after, since the gate records a
/// token's claims wherever the token was read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Attribute {
    /// The mechanism's name — `mutual-tls`, `jwt`, `ip`.
    Mechanism,
    /// The identity class, in the Foundation's words — `highAssurance`,
    /// `federated`, `sharedSecret`, `anonymous`.
    Class,
    /// `authenticates` or `identifies`.
    Assurance,
    /// The Party the identity resolved to, as its identifier reads. Absent
    /// where it resolved to none.
    Party,
    /// The value the identity presented — `CN=partner-x.example`.
    Value,
    /// A claim or any other evidence the gate recorded, by name. Absent
    /// where the record carries none under that name.
    Evidence(String),
    /// `receive`, `process` or `send`.
    Action,
    /// The artifact the attempt is on, whatever it is.
    Artifact,
    /// The artifact where it is a Location — the attempt receives or sends.
    /// Absent on an Xmip Process, which is not a Location.
    Location,
    /// The Contract, where one has been identified.
    Contract,
    /// The Path, where one applies.
    Path,
}

impl Attribute {
    /// A claim or other evidence, by the name the gate recorded it under.
    #[must_use]
    pub fn evidence(name: impl Into<String>) -> Self {
        Self::Evidence(name.into())
    }

    /// What the record and the attempt say, or `None` where they say nothing.
    #[must_use]
    pub fn read(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<String> {
        let accountable = identity.accountable();

        match self {
            Self::Mechanism => Some(accountable.mechanism.name().to_string()),
            Self::Class => Some(accountable.class().to_string()),
            Self::Assurance => Some(
                match accountable.mechanism.assurance() {
                    Assurance::Identifies => "identifies",
                    Assurance::Authenticates => "authenticates",
                }
                .to_string(),
            ),
            Self::Party => accountable.party_id.map(|party| party.to_string()),
            Self::Value => Some(accountable.value.clone()),
            Self::Evidence(wanted) => std::iter::once(accountable)
                .chain(identity.message.as_ref())
                .flat_map(|held| held.evidence.iter())
                .find(|(name, _)| name == wanted)
                .map(|(_, value)| value.clone()),
            Self::Action => Some(attempt.action.to_string()),
            Self::Artifact => Some(attempt.artifact.clone()),
            Self::Location => match attempt.action {
                Action::Receive | Action::Send => Some(attempt.artifact.clone()),
                Action::Process => None,
            },
            Self::Contract => attempt.contract.clone(),
            Self::Path => attempt.path.clone(),
        }
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mechanism => f.write_str("mechanism"),
            Self::Class => f.write_str("class"),
            Self::Assurance => f.write_str("assurance"),
            Self::Party => f.write_str("party"),
            Self::Value => f.write_str("value"),
            Self::Evidence(name) => write!(f, "evidence '{name}'"),
            Self::Action => f.write_str("action"),
            Self::Artifact => f.write_str("artifact"),
            Self::Location => f.write_str("location"),
            Self::Contract => f.write_str("contract"),
            Self::Path => f.write_str("path"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, PartyId, mechanism};

    fn facts() -> IdentityFacts {
        IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::mutual_tls(),
                "CN=partner-x.example",
                Established::Passed,
                Verified::Proven,
            )
            .resolving_to(PartyId::new(7))
            .with_evidence("issuer", "CN=Example CA"),
            Some(
                AuthenticatedIdentity::new(
                    mechanism::jwt(),
                    "sub=alice",
                    Established::Passed,
                    Verified::Proven,
                )
                .with_evidence("department", "billing"),
            ),
        )
    }

    #[test]
    fn an_attribute_reads_the_accountable_identity_and_the_attempt() {
        let attempt = Attempt::new(Action::Receive, "partner-x").on_contract("X12-850");
        let read = |attribute: Attribute| attribute.read(&facts(), &attempt);

        assert_eq!(read(Attribute::Mechanism).as_deref(), Some("mutual-tls"));
        assert_eq!(read(Attribute::Class).as_deref(), Some("highAssurance"));
        assert_eq!(read(Attribute::Assurance).as_deref(), Some("authenticates"));
        assert_eq!(
            read(Attribute::Party).as_deref(),
            Some("00000000-0000-0000-0000-000000000007")
        );
        assert_eq!(
            read(Attribute::Value).as_deref(),
            Some("CN=partner-x.example")
        );
        assert_eq!(read(Attribute::Action).as_deref(), Some("receive"));
        assert_eq!(read(Attribute::Artifact).as_deref(), Some("partner-x"));
        assert_eq!(read(Attribute::Contract).as_deref(), Some("X12-850"));
        assert_eq!(read(Attribute::Path), None);
    }

    #[test]
    fn evidence_is_found_on_either_layer_and_a_process_is_not_a_location() {
        let process = Attempt::new(Action::Process, "Approval");

        assert_eq!(
            Attribute::evidence("issuer")
                .read(&facts(), &process)
                .as_deref(),
            Some("CN=Example CA")
        );
        assert_eq!(
            Attribute::evidence("department")
                .read(&facts(), &process)
                .as_deref(),
            Some("billing")
        );
        assert_eq!(Attribute::evidence("group").read(&facts(), &process), None);
        assert_eq!(Attribute::Location.read(&facts(), &process), None);
        assert_eq!(
            Attribute::Location
                .read(&facts(), &Attempt::new(Action::Send, "Billing"))
                .as_deref(),
            Some("Billing")
        );
    }
}
