#![forbid(unsafe_code)]

//! The abac authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: attribute rules over the identity's
//! facts and the attempt (ADR-0050 section 5). A [`Rule`] permits or denies
//! where its [`Condition`] holds, and a condition compares an [`Attribute`]
//! — the mechanism, its class and assurance, the Party, a claim or other
//! evidence by name, the action, the artifact, the Location — with a value
//! by equals, not-equals, in or starts-with, combined with all-of and any-of.
//! Rules are built from values; this crate has no rule language of its own
//! to parse, because a deployment that wants one has `policy` and `cedar`.
//!
//! The first denying rule whose condition holds stands, naming the rule;
//! failing that, a permitting rule whose condition holds allows; where no
//! rule's condition holds the policy has no opinion and the question is the
//! next policy's. Nothing here verifies anything: the facts are what the
//! gates before this one recorded.

pub mod attribute;
pub mod condition;

use authorize::{Attempt, Authorizer, Decision};
use context::IdentityFacts;
use xcore::Layer;

pub use attribute::Attribute;
pub use condition::{Condition, Operator};

/// The manifest leaf, and the name a denial carries.
pub const NAME: &str = "abac";

/// What a rule concludes where its condition holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    /// The attempt is allowed, unless a denying rule also applies.
    Permit,
    /// The attempt is refused.
    Deny,
}

/// One rule: a name for the operator to find it by, an effect, a condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    name: String,
    effect: Effect,
    condition: Condition,
}

impl Rule {
    /// A rule that permits where the condition holds.
    #[must_use]
    pub fn permit(name: impl Into<String>, condition: Condition) -> Self {
        Self {
            name: name.into(),
            effect: Effect::Permit,
            condition,
        }
    }

    /// A rule that denies where the condition holds.
    #[must_use]
    pub fn deny(name: impl Into<String>, condition: Condition) -> Self {
        Self {
            name: name.into(),
            effect: Effect::Deny,
            condition,
        }
    }

    /// The name a denial by this rule carries.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What the rule concludes where it applies.
    #[must_use]
    pub const fn effect(&self) -> Effect {
        self.effect
    }
}

/// The attribute rules this deployment configures.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Abac {
    rules: Vec<Rule>,
}

impl Abac {
    /// A policy with no rules, which has no opinion on anything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule after the ones already there.
    #[must_use]
    pub fn rule(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }
}

impl Authorizer for Abac {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let mut permitted = false;

        for rule in &self.rules {
            if !rule.condition.holds(identity, attempt) {
                continue;
            }

            match rule.effect {
                Effect::Deny => {
                    return Some(Decision::denied(
                        NAME,
                        format!(
                            "rule '{}' denies {} on '{}'",
                            rule.name, attempt.action, attempt.artifact
                        ),
                    ));
                }
                Effect::Permit => permitted = true,
            }
        }

        permitted.then_some(Decision::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, PartyId, mechanism};

    fn token(department: &str) -> IdentityFacts {
        IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::jwt(),
                "sub=alice",
                Established::Passed,
                Verified::Proven,
            )
            .resolving_to(PartyId::new(7))
            .with_evidence("department", department),
            None,
        )
    }

    fn address() -> IdentityFacts {
        IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::ip(),
                "10.0.0.9",
                Established::Passed,
                Verified::Claimed,
            ),
            None,
        )
    }

    fn abac() -> Abac {
        Abac::new()
            .rule(Rule::permit(
                "billing-sends-billing",
                Condition::all_of([
                    Condition::equals(Attribute::evidence("department"), "billing"),
                    Condition::equals(Attribute::Action, "send"),
                    Condition::starts_with(Attribute::Location, "Billing"),
                ]),
            ))
            .rule(Rule::deny(
                "unproven-never-sends",
                Condition::all_of([
                    Condition::equals(Attribute::Assurance, "identifies"),
                    Condition::is_in(Attribute::Action, ["send", "process"]),
                ]),
            ))
            .rule(Rule::permit(
                "the-lan-sends",
                Condition::starts_with(Attribute::Value, "10."),
            ))
    }

    #[test]
    fn a_permitting_rule_whose_condition_holds_allows() {
        let decision = abac().decide(&token("billing"), &Attempt::new(Action::Send, "Billing-EU"));

        assert_eq!(decision, Some(Decision::Allowed));
        assert_eq!(abac().name(), "abac");
        assert_eq!(abac().layer(), Layer::Transport);
    }

    #[test]
    fn the_first_denial_stands_and_names_the_rule_whatever_else_permits() {
        // The address is on the LAN and the last rule would permit it; the
        // rule before it refuses whatever proves nothing, and a denial ends it.
        let decision = abac()
            .decide(&address(), &Attempt::new(Action::Send, "Billing-EU"))
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by abac: rule 'unproven-never-sends' denies send on 'Billing-EU'"
        );
    }

    #[test]
    fn no_rule_matching_is_no_opinion() {
        assert_eq!(
            abac().decide(&token("sales"), &Attempt::new(Action::Send, "Billing-EU")),
            None
        );
        assert_eq!(
            abac().decide(
                &token("billing"),
                &Attempt::new(Action::Process, "Billing-EU")
            ),
            None,
            "an Xmip Process is not a Location"
        );
        assert_eq!(
            Abac::new().decide(&address(), &Attempt::new(Action::Receive, "partner-x")),
            None
        );
    }

    #[test]
    fn a_rule_may_be_written_about_the_party_and_the_class() {
        let policy = Abac::new().rule(Rule::permit(
            "party-seven-federated",
            Condition::all_of([
                Condition::equals(Attribute::Party, PartyId::new(7).to_string()),
                Condition::not_equals(Attribute::Class, "anonymous"),
            ]),
        ));

        assert_eq!(
            policy.decide(&token("sales"), &Attempt::new(Action::Receive, "partner-x")),
            Some(Decision::Allowed)
        );
        assert_eq!(
            policy.decide(&address(), &Attempt::new(Action::Receive, "partner-x")),
            None,
            "an identity that resolved to no Party satisfies no rule about one"
        );
    }

    #[test]
    fn a_rule_says_its_name_and_its_effect() {
        let rule = Rule::deny("closed", Condition::all_of([]));

        assert_eq!(rule.name(), "closed");
        assert_eq!(rule.effect(), Effect::Deny);
    }
}
