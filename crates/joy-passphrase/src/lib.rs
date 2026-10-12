// Copyright (c) 2026 Joydev GmbH (joydev.com)
// SPDX-License-Identifier: MIT

//! joy-passphrase: how strong a passphrase is, judged the same way on
//! every surface (JI-01A5-93, CRYPT-0016-B0).
//!
//! The estimate is zxcvbn's (Dropbox; Wheeler and Lowe, "zxcvbn:
//! Low-Budget Password Strength Estimation", USENIX Security 2016), as
//! the Rust crate `zxcvbn` implements it. Its guess count becomes bits
//! (`log2(guesses)`), and the bits fall into five levels at fixed
//! thresholds. The crate's own 0 to 4 score is not used: it saturates
//! at 10^10 guesses, about 33 bit, which is a threshold for online
//! guessing, not for an attacker who holds the wrapped seed.
//!
//! The levels inform; nothing here enforces a minimum. The only
//! refusal is an empty passphrase, because an empty one cannot be
//! derived from. Nothing is normalised: the bytes judged here are the
//! bytes Argon2id will hash.
//!
//! The Rust crate counts guesses in a 64-bit integer and saturates at
//! 2^64, which the reference implementation (JavaScript, doubles) does
//! not. Where it saturates, [`strength`] redoes the arithmetic of the
//! sequence the crate chose in floating point, with the crate's own
//! formula (`l! × Π guesses + 10^(4(l-1))`), and never reports more than
//! the whole string as one brute-force guess (10 per character). Below
//! 64 bit the two agree exactly; above, the value is the crate's chosen
//! sequence, which the integer search may not have picked as the
//! smallest.
//!
//! The crate has no dependency on joy-crypt and builds for native
//! targets and for wasm32-unknown-unknown alike, so the CLI, the desktop
//! and the browser agree to the bit.

#![forbid(unsafe_code)]

use std::f64::consts::LOG2_10;

use thiserror::Error;
use zxcvbn::matching::patterns::MatchPattern;

/// Why a passphrase is not accepted at all.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("the passphrase is empty")]
    Empty,
}

/// The five levels, by entropy in bits. The German names, for the
/// documentation: ungenügend, genügend, gut, sehr gut, ausgezeichnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Below 28 bit: minutes to hours of offline guessing on one GPU.
    Insufficient,
    /// From 28 bit: days on one GPU, minutes with a farm; holds against
    /// online guessing only.
    Sufficient,
    /// From 45 bit: centuries on one GPU, weeks with ten thousand.
    Good,
    /// From 60 bit: out of reach for any farm.
    VeryGood,
    /// From 80 bit: beyond realistic compute; with the Argon2id work
    /// factor the effective cost is above 100 bit.
    Excellent,
}

/// The bit thresholds of [`Level::Sufficient`], [`Level::Good`],
/// [`Level::VeryGood`] and [`Level::Excellent`], in that order. The
/// time estimates in the level docs assume about a thousand Argon2id
/// guesses per second per GPU with joy-crypt's parameters (64 MiB, t=3).
pub const THRESHOLDS: [f64; 4] = [28.0, 45.0, 60.0, 80.0];

impl Level {
    /// The level the bits fall into.
    pub fn of(bits: f64) -> Level {
        if bits >= THRESHOLDS[3] {
            Level::Excellent
        } else if bits >= THRESHOLDS[2] {
            Level::VeryGood
        } else if bits >= THRESHOLDS[1] {
            Level::Good
        } else if bits >= THRESHOLDS[0] {
            Level::Sufficient
        } else {
            Level::Insufficient
        }
    }

    /// The level as a word, as the CLI and the app show it.
    pub fn label(self) -> &'static str {
        match self {
            Level::Insufficient => "insufficient",
            Level::Sufficient => "sufficient",
            Level::Good => "good",
            Level::VeryGood => "very good",
            Level::Excellent => "excellent",
        }
    }

    /// The level as a number from 1 to 5, for a bar of five segments.
    pub fn rank(self) -> u8 {
        match self {
            Level::Insufficient => 1,
            Level::Sufficient => 2,
            Level::Good => 3,
            Level::VeryGood => 4,
            Level::Excellent => 5,
        }
    }
}

/// What the meter shows: the entropy in bits and the level it falls into.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Strength {
    /// `log2` of zxcvbn's guess estimate. Zero for an empty passphrase.
    pub bits: f64,
    pub level: Level,
}

/// Judge a passphrase. Every surface calls this on every keystroke, so
/// it takes the text as it stands, empty included.
pub fn strength(passphrase: &str) -> Strength {
    if passphrase.is_empty() {
        return Strength {
            bits: 0.0,
            level: Level::Insufficient,
        };
    }
    let estimate = zxcvbn::zxcvbn(passphrase, &[]);
    let bits = bits_of(passphrase, &estimate);
    Strength {
        bits,
        level: Level::of(bits),
    }
}

/// `log2` of the guess count: the crate's own while its integer holds,
/// else the same formula over the chosen sequence in floating point.
fn bits_of(passphrase: &str, estimate: &zxcvbn::Entropy) -> f64 {
    if estimate.guesses() < u64::MAX {
        return estimate.guesses_log10() * LOG2_10;
    }
    recompute(passphrase, estimate)
}

/// The crate's formula over its chosen sequence, in floating point.
fn recompute(passphrase: &str, estimate: &zxcvbn::Entropy) -> f64 {
    let sequence = estimate.sequence();
    let l = sequence.len();
    // log2(l!) + Σ log2(guesses of each match)
    let mut product = (1..=l).map(|k| (k as f64).log2()).sum::<f64>();
    for m in sequence {
        product += match m.pattern {
            // 10 per character, and one more than the smallest submatch
            // for a single character, as scoring.rs estimates it
            MatchPattern::BruteForce => {
                let n = m.token.chars().count();
                if n == 1 {
                    11f64.log2()
                } else {
                    n as f64 * LOG2_10
                }
            }
            _ => (m.guesses.unwrap_or(1) as f64).log2(),
        };
    }
    // the additive term: 10^(4(l-1)) for a sequence of more than one match
    let total = if l > 1 {
        let additive = 4.0 * (l as f64 - 1.0) * LOG2_10;
        log2_sum(product, additive)
    } else {
        product
    };
    // the whole string as one brute-force match is always a valid sequence
    let whole = passphrase.chars().count() as f64 * LOG2_10;
    total.min(whole)
}

/// `log2(2^a + 2^b)` without leaving log space.
fn log2_sum(a: f64, b: f64) -> f64 {
    let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
    hi + (1.0 + 2f64.powf(lo - hi)).log2()
}

/// Whether a passphrase may be set at all. Only an empty one is refused;
/// the strength is shown, never enforced (JI-01A5-93 point 5).
pub fn accept(passphrase: &str) -> Result<(), Error> {
    if passphrase.is_empty() {
        return Err(Error::Empty);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_thresholds_map_just_below_and_at_each_boundary() {
        assert_eq!(Level::of(0.0), Level::Insufficient);
        assert_eq!(Level::of(27.99), Level::Insufficient);
        assert_eq!(Level::of(28.0), Level::Sufficient);
        assert_eq!(Level::of(44.99), Level::Sufficient);
        assert_eq!(Level::of(45.0), Level::Good);
        assert_eq!(Level::of(59.99), Level::Good);
        assert_eq!(Level::of(60.0), Level::VeryGood);
        assert_eq!(Level::of(79.99), Level::VeryGood);
        assert_eq!(Level::of(80.0), Level::Excellent);
        assert_eq!(Level::of(200.0), Level::Excellent);
    }

    #[test]
    fn the_ranks_and_labels_follow_the_order() {
        let levels = [
            Level::Insufficient,
            Level::Sufficient,
            Level::Good,
            Level::VeryGood,
            Level::Excellent,
        ];
        for (i, level) in levels.iter().enumerate() {
            assert_eq!(level.rank() as usize, i + 1);
        }
        assert_eq!(Level::Excellent.label(), "excellent");
        assert_eq!(Level::VeryGood.label(), "very good");
        assert!(Level::Insufficient < Level::Excellent);
    }

    #[test]
    fn known_inputs_land_where_the_decision_says() {
        assert_eq!(strength("q w e").level, Level::Insufficient);
        assert_eq!(strength("a a a").level, Level::Insufficient);
        assert_eq!(strength("password123").level, Level::Insufficient);
        assert_eq!(strength("qwerty").level, Level::Insufficient);
        assert_eq!(strength("Tr0ub4dor&3").level, Level::Sufficient);
        // zxcvbn counts ten guesses per character of random text, so
        // fourteen of them are Good, and twenty-five Excellent
        assert_eq!(strength("k7#Qz9!vLp2&Rm").level, Level::Good);
        assert_eq!(
            strength("k7#Qz9!vLp2&Rm8xW!c4Nb@Yq").level,
            Level::Excellent
        );
        // four Diceware words with their spaces are seven matches, and
        // zxcvbn's additive term alone makes that about 80 bit
        assert!(strength("correct horse battery staple").level >= Level::VeryGood);
        assert!(strength("ladle quartz nimbus fjord carapace velvet").level == Level::Excellent);
    }

    /// Below the crate's integer ceiling the floating point arithmetic
    /// and the crate's own number are the same number.
    #[test]
    fn the_recomputation_agrees_with_the_crate_where_the_crate_can_count() {
        for passphrase in [
            "the quick brown fox",
            "Tr0ub4dor&3",
            "k7#Qz9!vLp2&Rm",
            "q w e",
        ] {
            let estimate = zxcvbn::zxcvbn(passphrase, &[]);
            assert!(estimate.guesses() < u64::MAX, "{passphrase} saturates");
            let crate_bits = estimate.guesses_log10() * LOG2_10;
            let recomputed = recompute(passphrase, &estimate);
            assert!(
                (crate_bits - recomputed).abs() < 1e-3,
                "{passphrase}: crate {crate_bits}, recomputed {recomputed}"
            );
        }
    }

    /// Above the ceiling the number keeps growing with the passphrase
    /// instead of stopping at 64.
    #[test]
    fn the_bits_keep_growing_past_the_integer_ceiling() {
        let four = strength("ladle quartz nimbus fjord").bits;
        let six = strength("ladle quartz nimbus fjord carapace velvet").bits;
        let eight = strength("ladle quartz nimbus fjord carapace velvet orchid tundra").bits;
        assert!(four > 64.0, "{four}");
        assert!(six > four, "{six} > {four}");
        assert!(eight > six, "{eight} > {six}");
        // and never more than the whole string as one brute-force guess
        assert!(eight <= 56.0 * LOG2_10 + 1e-9, "{eight}");
    }

    #[test]
    fn the_bits_grow_with_the_passphrase_and_start_at_zero() {
        assert_eq!(strength("").bits, 0.0);
        let one = strength("ladle").bits;
        let two = strength("ladle quartz").bits;
        let three = strength("ladle quartz nimbus").bits;
        assert!(one > 0.0);
        assert!(two > one);
        assert!(three > two);
    }

    #[test]
    fn only_the_empty_passphrase_is_refused() {
        assert_eq!(accept(""), Err(Error::Empty));
        assert_eq!(accept("q"), Ok(()));
        assert_eq!(accept(" "), Ok(()));
        assert_eq!(accept("q w e"), Ok(()));
    }
}
