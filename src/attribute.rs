//! An attribute: one thing a rule's expression may read off the record or
//! the attempt, by the name the expression writes it as.

use authorize::{Action, Attempt};
use context::IdentityFacts;
use expression::{Condition, Names, Operand};
use std::cell::OnceCell;
use std::fmt;
use xcore::Assurance;

/// The prefix of a name that reads a claim or other evidence by its name:
/// `evidence:department`.
pub const EVIDENCE: &str = "evidence:";

/// One thing a rule may read, and the name its expression reads it by:
/// `mechanism`, `class`, `assurance`, `party`, `value`, `action`,
/// `artifact`, `location`, `contract`, `path`, or `evidence:` before a
/// claim's name.
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
    /// The value the identity presented — `CN=party-x.example`.
    Value,
    /// A claim or any other evidence the gate recorded, by name. Absent
    /// where the record carries none under that name.
    Evidence(String),
    /// `receive`, `process` or `send`.
    Action,
    /// The artifact the attempt is on, whatever it is.
    Artifact,
    /// The artifact where it is a Location — the attempt receives or sends.
    /// Absent on a Work Process, which is not a Location.
    Location,
    /// The Contract, where one has been identified.
    Contract,
    /// The Path, where one applies.
    Path,
}

impl Attribute {
    /// Every attribute read by a word of its own, in the order a designer
    /// offers them; evidence is read by [`EVIDENCE`] and a claim's name.
    pub const WORDS: [Self; 10] = [
        Self::Mechanism,
        Self::Class,
        Self::Assurance,
        Self::Party,
        Self::Value,
        Self::Action,
        Self::Artifact,
        Self::Location,
        Self::Contract,
        Self::Path,
    ];

    /// A claim or other evidence, by the name the gate recorded it under.
    #[must_use]
    pub fn evidence(name: impl Into<String>) -> Self {
        Self::Evidence(name.into())
    }

    /// The attribute an expression's `name` reads, or `None` where it reads
    /// none.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name.strip_prefix(EVIDENCE) {
            Some(claim) => Some(Self::evidence(claim)),
            None => Self::WORDS
                .into_iter()
                .find(|attribute| attribute.word() == Some(name)),
        }
    }

    /// It begins with `prefix`, every `%`, `_` and `\` in the prefix
    /// matching only itself (`expression::Condition::starts_with`):
    /// a rule about a Party's or a Location's prefix names that prefix and
    /// nothing wider.
    #[must_use]
    pub fn starts_with(&self, prefix: &str) -> Condition {
        Condition::starts_with(Operand::Name(self.to_string()), prefix)
    }

    /// The word it is read by; `None` for evidence, read by its claim's
    /// name.
    #[must_use]
    pub const fn word(&self) -> Option<&'static str> {
        Some(match self {
            Self::Mechanism => "mechanism",
            Self::Class => "class",
            Self::Assurance => "assurance",
            Self::Party => "party",
            Self::Value => "value",
            Self::Action => "action",
            Self::Artifact => "artifact",
            Self::Location => "location",
            Self::Contract => "contract",
            Self::Path => "path",
            Self::Evidence(_) => return None,
        })
    }
}

/// The name an expression reads it by.
impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self, self.word()) {
            (Self::Evidence(claim), _) => write!(f, "{EVIDENCE}{claim}"),
            (_, word) => f.write_str(word.unwrap_or_default()),
        }
    }
}

/// What a rule's expression reads: the record and the attempt, each
/// attribute by its name. A word the record holds as a value of its own —
/// the class, the action, the Party's identifier — is written once, the
/// first time a name asks for it.
pub(crate) struct Read<'a> {
    identity: &'a IdentityFacts,
    attempt: &'a Attempt,
    class: OnceCell<String>,
    action: OnceCell<String>,
    party: OnceCell<Option<String>>,
}

impl<'a> Read<'a> {
    pub(crate) fn new(identity: &'a IdentityFacts, attempt: &'a Attempt) -> Self {
        Self {
            identity,
            attempt,
            class: OnceCell::new(),
            action: OnceCell::new(),
            party: OnceCell::new(),
        }
    }

    /// What the record and the attempt say of `attribute`, or `None` where
    /// they say nothing.
    pub(crate) fn read(&self, attribute: &Attribute) -> Option<&str> {
        let accountable = self.identity.accountable();
        let attempt = self.attempt;

        match attribute {
            Attribute::Mechanism => Some(accountable.mechanism.name()),
            Attribute::Class => Some(self.class.get_or_init(|| accountable.class().to_string())),
            Attribute::Assurance => Some(match accountable.mechanism.assurance() {
                Assurance::Identifies => "identifies",
                Assurance::Authenticates => "authenticates",
            }),
            Attribute::Party => self
                .party
                .get_or_init(|| accountable.party_id.map(|party| party.to_string()))
                .as_deref(),
            Attribute::Value => Some(&accountable.value),
            Attribute::Evidence(wanted) => {
                self.identity.held().find_map(|held| held.evidence(wanted))
            }
            Attribute::Action => Some(self.action.get_or_init(|| attempt.action.to_string())),
            Attribute::Artifact => Some(&attempt.artifact),
            Attribute::Location => match attempt.action {
                Action::Receive | Action::Send => Some(&attempt.artifact),
                Action::Process => None,
            },
            Attribute::Contract => attempt.contract.as_deref(),
            Attribute::Path => attempt.path.as_deref(),
        }
    }
}

impl Names for Read<'_> {
    fn value(&self, name: &str) -> Option<&str> {
        self.read(&Attribute::named(name)?)
    }

    fn absent(&self, name: &str) -> String {
        format!("the identity's facts and the attempt say nothing of {name}")
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
                "CN=party-x.example",
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
        let facts = facts();
        let attempt = Attempt::now(Action::Receive, "party-x").on_contract("X12-850");
        let read = Read::new(&facts, &attempt);

        assert_eq!(read.value("mechanism"), Some("mutual-tls"));
        assert_eq!(read.value("class"), Some("highAssurance"));
        assert_eq!(read.value("assurance"), Some("authenticates"));
        assert_eq!(
            read.value("party"),
            Some("00000000-0000-0000-0000-000000000007")
        );
        assert_eq!(read.value("value"), Some("CN=party-x.example"));
        assert_eq!(read.value("action"), Some("receive"));
        assert_eq!(read.value("artifact"), Some("party-x"));
        assert_eq!(read.value("contract"), Some("X12-850"));
        assert_eq!(read.value("path"), None);
        assert_eq!(read.value("Mechanism"), None, "a word is read as written");
    }

    #[test]
    fn evidence_is_found_on_either_layer_and_a_process_is_not_a_location() {
        let facts = facts();
        let process = Attempt::now(Action::Process, "Approval");
        let read = Read::new(&facts, &process);

        assert_eq!(read.value("evidence:issuer"), Some("CN=Example CA"));
        assert_eq!(read.value("evidence:department"), Some("billing"));
        assert_eq!(read.value("evidence:group"), None);
        assert_eq!(read.value("location"), None);
        let send = Attempt::now(Action::Send, "Billing");
        assert_eq!(Read::new(&facts, &send).value("location"), Some("Billing"));
    }

    #[test]
    fn every_attribute_is_named_by_what_it_writes() {
        let every = Attribute::WORDS
            .into_iter()
            .chain([Attribute::evidence("department")]);
        for attribute in every {
            assert_eq!(Attribute::named(&attribute.to_string()), Some(attribute));
        }
        assert_eq!(Attribute::evidence("group").to_string(), "evidence:group");
        assert_eq!(Attribute::named("header:http.x-channel"), None);
    }
}
