# 5. MSRV floor of 1.93, set by `sevenz-rust2` (capability over a lower MSRV)

Date: 2026-07-24
Status: Accepted

> Reverse-documented from the `Cargo.toml` `rust-version` comment,
> `rust-toolchain.toml`, and commit `46b201a` ("honest MSRV/license fixes").

## Context

The fleet MSRV policy (`~/src/ronin-issen/CLAUDE.md`, "Rust MSRV & Toolchain")
keeps *published libraries* at a low, CI-verified MSRV floor (`1.75`/`1.80`) as a
compatibility promise, separate from the dev toolchain (pinned to current
stable). Archive-core is a published library, so a low floor would be the default
preference.

But archive-core hard-depends on `sevenz-rust2` for 7z decode (ADR 0004), and
that crate requires rustc 1.93. The fleet's batteries-included standard is
explicit that **capability yields precedence over a low declared MSRV**: a codec
the examiner needs is worth the floor bump.

## Decision

1. **Declare `rust-version = "1.93"`** in `[workspace.package]` (`Cargo.toml`),
   with the reason recorded inline: "The batteries-included reader depends on
   `sevenz-rust2` (pure-Rust 7z), which requires rustc 1.93 — that dependency sets
   the real MSRV floor. Capability (7z decode) wins over a lower declared MSRV per
   fleet policy." The floor is honest — it matches what actually compiles — rather
   than an aspirational lower number.
2. **Keep the dev toolchain pinned separately** at current stable
   (`rust-toolchain.toml` `channel = "1.96.0"`, with `clippy`/`rustfmt`
   components), per the split between the pinned dev toolchain and the
   downstream-facing declared MSRV.

## Consequences

- Consumers on rustc < 1.93 cannot use `archive-core`; this is accepted as the
  cost of shipping in-the-box 7z decode rather than feature-gating it away.
- The floor moves only when a dependency genuinely requires it — not to chase the
  dev toolchain. Should the 7z reader ever relax its requirement, the floor can
  drop; the number tracks a real dependency constraint, so it stays verifiable.
