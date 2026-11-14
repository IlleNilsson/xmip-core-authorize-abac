#![forbid(unsafe_code)]

//! The abac authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: attribute rules over the identity's
//! facts and the attempt (ADR-0050 section 5). A [`Rule`] permits or denies
//! where its condition holds. The condition is written in Xmip's one
//! expression language (ADR-0066 clause 2, `xmip-core-path`'s
//! `expression`), over the names of the [`Attribute`]s — the mechanism, its
//! class and assurance, the Party, a claim or other evidence by name, the
//! action, the artifact, the Location: `evidence:department = 'billing' and
//! location like 'Billing%'`. It is compiled once and decided from its tree,
//! in the language's three truths: an attribute the record does not carry
//! is unknown, and only true holds, so a rule that denies whoever is not
//! Party 7 is not satisfied by an identity that resolved to no Party at
//! all. This crate has no condition of its own to parse or decide.
//!
//! The first denying rule whose condition holds stands, naming the rule;
//! failing that, a permitting rule whose condition holds allows; where no
//! rule's condition holds the policy has no opinion and the question is the
//! next policy's. Nothing here verifies anything: the facts are what the
//! gates before this one recorded.

pub mod attribute;

use attribute::Read;
use authorize::{Attempt, AuthorizeError, Authorizer, Decision};
use context::IdentityFacts;
use path::expression::Expression;
use xcore::Layer;

pub use attribute::{Attribute, EVIDENCE};

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
    condition: Expression,
}

impl Rule {
    /// A rule that permits where the condition holds.
    ///
    /// # Errors
    /// The condition reads a name that is no [`Attribute`].
    pub fn permit(name: impl Into<String>, condition: Expression) -> Result<Self, AuthorizeError> {
        Self::new(name.into(), Effect::Permit, condition)
    }

    /// A rule that denies where the condition holds.
    ///
    /// # Errors
    /// The condition reads a name that is no [`Attribute`].
    pub fn deny(name: impl Into<String>, condition: Expression) -> Result<Self, AuthorizeError> {
        Self::new(name.into(), Effect::Deny, condition)
    }

    /// A name no attribute answers would leave the condition unknown at
    /// every attempt, so it is refused here, once, in words.
    fn new(name: String, effect: Effect, condition: Expression) -> Result<Self, AuthorizeError> {
        if let Some(unread) = condition
            .names()
            .into_iter()
            .find(|read| Attribute::named(read).is_none())
        {
            let words: Vec<&str> = Attribute::WORDS
                .iter()
                .filter_map(Attribute::word)
                .collect();
            return Err(AuthorizeError::new(format!(
                "rule '{name}' reads {unread}, which is no attribute: it reads {}, or \
                 {EVIDENCE} and a claim's name",
                words.join(", ")
            )));
        }
        Ok(Self {
            name,
            effect,
            condition,
        })
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

    /// The condition, as it was written.
    #[must_use]
    pub const fn condition(&self) -> &Expression {
        &self.condition
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
        let read = Read::new(identity, attempt);
        let mut permitted = false;

        for rule in &self.rules {
            if !rule.condition.evaluate(&read).holds() {
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

    fn expression(text: &str) -> Expression {
        Expression::parse(text).expect("an expression")
    }

    fn permit(name: &str, condition: &str) -> Rule {
        Rule::permit(name, expression(condition)).expect("a rule")
    }

    fn abac() -> Abac {
        Abac::new()
            .rule(permit(
                "billing-sends-billing",
                "evidence:department = 'billing' and action = 'send' and location like 'Billing%'",
            ))
            .rule(
                Rule::deny(
                    "unproven-never-sends",
                    expression("assurance = 'identifies' and action in ('send', 'process')"),
                )
                .expect("a rule"),
            )
            .rule(permit("the-lan-sends", "value like '10.%'"))
    }

    /// Whether `condition` holds for a token from billing sending to
    /// Billing-EU.
    fn holds(condition: &str) -> bool {
        let rule = permit("asked", condition);
        let attempt = Attempt::now(Action::Send, "Billing-EU");
        Abac::new().rule(rule).decide(&token("billing"), &attempt) == Some(Decision::Allowed)
    }

    #[test]
    fn each_operator_compares_what_was_read_with_what_the_rule_names() {
        assert!(holds("mechanism = 'jwt'"));
        assert!(!holds("mechanism = 'ip'"));
        assert!(holds("action <> 'receive'"));
        assert!(!holds("action <> 'send'"));
        assert!(holds("evidence:department in ('sales', 'billing')"));
        assert!(!holds("evidence:department in ('sales')"));
        assert!(holds("artifact like 'Billing%'"));
        assert!(!holds("artifact like 'Shipping%'"));
    }

    #[test]
    fn an_absent_attribute_satisfies_nothing_not_even_not_equals() {
        assert!(!holds("contract = 'anything'"));
        assert!(!holds("contract <> 'anything'"));
        assert!(!holds("evidence:group <> 'admins'"));
        assert!(!holds("not evidence:group = 'admins'"));
    }

    #[test]
    fn and_needs_every_one_and_or_needs_one() {
        let (yes, no) = ("action = 'send'", "action = 'receive'");

        assert!(holds(&format!("{yes} and {yes}")));
        assert!(!holds(&format!("{yes} and {no}")));
        assert!(holds(&format!("{no} or {yes}")));
        assert!(!holds(&format!("{no} or {no}")));
        assert!(holds("true"));
        assert!(!holds("false"));
        assert!(holds(&format!("{yes} and ({no} or ({yes}))")));
    }

    #[test]
    fn a_prefix_rule_s_underscore_and_percent_match_only_themselves() {
        let prefixed = |prefix: &str| {
            let condition = Expression::from_condition(Attribute::Artifact.starts_with(prefix))
                .expect("compiles");
            Abac::new().rule(Rule::permit("prefixed", condition).expect("a rule"))
        };
        let allows = |policy: &Abac, artifact: &str| {
            let attempt = Attempt::now(Action::Send, artifact);
            policy.decide(&token("billing"), &attempt) == Some(Decision::Allowed)
        };

        let underscore = prefixed("Billing_");
        assert!(allows(&underscore, "Billing_EU"));
        assert!(
            !allows(&underscore, "BillingXEU"),
            "_ is not any one character"
        );
        let percent = prefixed("100%");
        assert!(allows(&percent, "100%-off"));
        assert!(!allows(&percent, "1000"), "% is not any run");
        let backslash = prefixed(r"a\b");
        assert!(allows(&backslash, r"a\bc"));
        assert!(!allows(&backslash, "abc"));
    }

    #[test]
    fn a_rule_that_reads_no_attribute_is_refused_in_words() {
        let refused = Rule::deny("typo", expression("mechansim = 'ip'")).expect_err("no attribute");

        assert!(
            refused.to_string().contains("rule 'typo' reads mechansim"),
            "{refused}"
        );
        assert!(refused.to_string().contains("evidence:"), "{refused}");
    }

    #[test]
    fn a_permitting_rule_whose_condition_holds_allows() {
        let decision = abac().decide(&token("billing"), &Attempt::now(Action::Send, "Billing-EU"));

        assert_eq!(decision, Some(Decision::Allowed));
        assert_eq!(abac().name(), "abac");
        assert_eq!(abac().layer(), Layer::Transport);
    }

    #[test]
    fn the_first_denial_stands_and_names_the_rule_whatever_else_permits() {
        // The address is on the LAN and the last rule would permit it; the
        // rule before it refuses whatever proves nothing, and a denial ends it.
        let decision = abac()
            .decide(&address(), &Attempt::now(Action::Send, "Billing-EU"))
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by abac: rule 'unproven-never-sends' denies send on 'Billing-EU'"
        );
    }

    #[test]
    fn no_rule_matching_is_no_opinion() {
        assert_eq!(
            abac().decide(&token("sales"), &Attempt::now(Action::Send, "Billing-EU")),
            None
        );
        assert_eq!(
            abac().decide(
                &token("billing"),
                &Attempt::now(Action::Process, "Billing-EU")
            ),
            None,
            "a Work Process is not a Location"
        );
        assert_eq!(
            Abac::new().decide(&address(), &Attempt::now(Action::Receive, "party-x")),
            None
        );
    }

    #[test]
    fn a_rule_may_be_written_about_the_party_and_the_class() {
        let party = PartyId::new(7);
        let policy = Abac::new().rule(permit(
            "party-seven-federated",
            &format!("party = '{party}' and class <> 'anonymous'"),
        ));

        assert_eq!(
            policy.decide(&token("sales"), &Attempt::now(Action::Receive, "party-x")),
            Some(Decision::Allowed)
        );
        assert_eq!(
            policy.decide(&address(), &Attempt::now(Action::Receive, "party-x")),
            None,
            "an identity that resolved to no Party satisfies no rule about one"
        );
    }

    #[test]
    fn a_rule_says_its_name_and_its_effect() {
        let rule = Rule::deny("closed", Expression::everything()).expect("a rule");

        assert_eq!(rule.name(), "closed");
        assert_eq!(rule.effect(), Effect::Deny);
        assert_eq!(rule.condition().text(), "true");
    }
}
