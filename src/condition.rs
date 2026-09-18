//! A condition: comparisons of attributes with values, combined.

use crate::attribute::Attribute;
use authorize::Attempt;
use context::IdentityFacts;

/// How an attribute is compared with the values a rule names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operator {
    /// The attribute is exactly the value.
    Equals,
    /// The attribute is present and is not the value.
    NotEquals,
    /// The attribute is one of the values.
    In,
    /// The attribute begins with the value.
    StartsWith,
}

/// When a rule applies.
///
/// An attribute the record does not carry satisfies no comparison, not even
/// [`Operator::NotEquals`]: a rule that denies whoever is not Party 7 was not
/// written about an identity that resolved to no Party at all, and a rule
/// that permits on it must not be satisfied by silence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Condition {
    /// One attribute compared with one or more values.
    Compare {
        /// What is read.
        attribute: Attribute,
        /// How it is compared.
        operator: Operator,
        /// What it is compared with. One value, except for [`Operator::In`].
        values: Vec<String>,
    },
    /// Every condition holds. An empty list holds.
    All(Vec<Condition>),
    /// At least one condition holds. An empty list does not.
    Any(Vec<Condition>),
}

impl Condition {
    /// The attribute is exactly this value.
    #[must_use]
    pub fn equals(attribute: Attribute, value: impl Into<String>) -> Self {
        Self::compare(attribute, Operator::Equals, vec![value.into()])
    }

    /// The attribute is present and is not this value.
    #[must_use]
    pub fn not_equals(attribute: Attribute, value: impl Into<String>) -> Self {
        Self::compare(attribute, Operator::NotEquals, vec![value.into()])
    }

    /// The attribute is one of these values.
    #[must_use]
    pub fn is_in<V: Into<String>>(
        attribute: Attribute,
        values: impl IntoIterator<Item = V>,
    ) -> Self {
        let values = values.into_iter().map(Into::into).collect();
        Self::compare(attribute, Operator::In, values)
    }

    /// The attribute begins with this value.
    #[must_use]
    pub fn starts_with(attribute: Attribute, value: impl Into<String>) -> Self {
        Self::compare(attribute, Operator::StartsWith, vec![value.into()])
    }

    /// Every one of these holds.
    #[must_use]
    pub fn all_of(conditions: impl IntoIterator<Item = Self>) -> Self {
        Self::All(conditions.into_iter().collect())
    }

    /// At least one of these holds.
    #[must_use]
    pub fn any_of(conditions: impl IntoIterator<Item = Self>) -> Self {
        Self::Any(conditions.into_iter().collect())
    }

    fn compare(attribute: Attribute, operator: Operator, values: Vec<String>) -> Self {
        Self::Compare {
            attribute,
            operator,
            values,
        }
    }

    /// Whether the condition holds for this identity attempting this.
    #[must_use]
    pub fn holds(&self, identity: &IdentityFacts, attempt: &Attempt) -> bool {
        match self {
            Self::All(conditions) => conditions
                .iter()
                .all(|condition| condition.holds(identity, attempt)),
            Self::Any(conditions) => conditions
                .iter()
                .any(|condition| condition.holds(identity, attempt)),
            Self::Compare {
                attribute,
                operator,
                values,
            } => attribute.read(identity, attempt).is_some_and(|read| {
                let mut values = values.iter();

                match operator {
                    Operator::Equals | Operator::In => values.any(|value| *value == read),
                    Operator::NotEquals => values.all(|value| *value != read),
                    Operator::StartsWith => values.any(|value| read.starts_with(value.as_str())),
                }
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, mechanism};

    fn facts() -> IdentityFacts {
        IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::jwt(),
                "sub=alice",
                Established::Passed,
                Verified::Proven,
            )
            .with_evidence("department", "billing"),
            None,
        )
    }

    fn holds(condition: &Condition) -> bool {
        condition.holds(&facts(), &Attempt::new(Action::Send, "Billing-EU"))
    }

    #[test]
    fn each_operator_compares_what_was_read_with_what_the_rule_names() {
        assert!(holds(&Condition::equals(Attribute::Mechanism, "jwt")));
        assert!(!holds(&Condition::equals(Attribute::Mechanism, "ip")));
        assert!(holds(&Condition::not_equals(Attribute::Action, "receive")));
        assert!(!holds(&Condition::not_equals(Attribute::Action, "send")));
        assert!(holds(&Condition::is_in(
            Attribute::evidence("department"),
            ["sales", "billing"]
        )));
        assert!(!holds(&Condition::is_in(
            Attribute::evidence("department"),
            ["sales"]
        )));
        assert!(holds(&Condition::starts_with(
            Attribute::Artifact,
            "Billing"
        )));
        assert!(!holds(&Condition::starts_with(
            Attribute::Artifact,
            "Shipping"
        )));
    }

    #[test]
    fn an_absent_attribute_satisfies_nothing_not_even_not_equals() {
        assert!(!holds(&Condition::equals(Attribute::Party, "anything")));
        assert!(!holds(&Condition::not_equals(Attribute::Party, "anything")));
        assert!(!holds(&Condition::not_equals(
            Attribute::evidence("group"),
            "admins"
        )));
    }

    #[test]
    fn all_of_needs_every_one_and_any_of_needs_one() {
        let yes = || Condition::equals(Attribute::Action, "send");
        let no = || Condition::equals(Attribute::Action, "receive");

        assert!(holds(&Condition::all_of([yes(), yes()])));
        assert!(!holds(&Condition::all_of([yes(), no()])));
        assert!(holds(&Condition::any_of([no(), yes()])));
        assert!(!holds(&Condition::any_of([no(), no()])));
        assert!(holds(&Condition::all_of([])));
        assert!(!holds(&Condition::any_of([])));
        assert!(holds(&Condition::all_of([
            yes(),
            Condition::any_of([no(), Condition::all_of([yes()])])
        ])));
    }
}
