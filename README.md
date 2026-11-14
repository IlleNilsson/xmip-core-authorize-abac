# xmip-core-authorize-abac

Attribute-based authorization: rules that permit or deny where a condition holds over attributes of the identity's facts and the attempt. A technology of [xmip-core-authorize](https://github.com/IlleNilsson/xmip-core-authorize).

A condition is written in Xmip's one expression language, [xmip-core-path](https://github.com/IlleNilsson/xmip-core-path)'s `expression` (ADR-0066 clause 2), over the attributes' names: `mechanism`, `class`, `assurance`, `party`, `value`, `action`, `artifact`, `location`, `contract`, `path`, and `evidence:` before a claim's name.

```text
evidence:department = 'billing' and action in ('send', 'process') and location like 'Billing%'
```

An attribute the record does not carry is unknown, and only a condition that is true applies. A rule whose condition reads a name that is no attribute is refused when it is made. A prefix rule is `Attribute::starts_with`, which writes `like 'prefix%' escape '\'`, so a `%`, `_` or `\` in the prefix matches only itself.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
