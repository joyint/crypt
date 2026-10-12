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
//! The Rust crate counts guesses in a 64-bit integer and stops at 2^64:
//! everything beyond reads as exactly 64 bit, and there the five levels
//! end too. The top level is that ceiling, shown as "entropy >64 bit",
//! because the number beyond it is not known (CRYPT-0018-87, the reminder
//! for the day upstream counts further).
//!
//! The crate has no dependency on joy-crypt and builds for native
//! targets and for wasm32-unknown-unknown alike, so the CLI, the desktop
//! and the browser agree to the bit.

#![forbid(unsafe_code)]

#[cfg(feature = "estimate")]
use std::f64::consts::LOG2_10;

use thiserror::Error;

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
    /// The estimator's ceiling, 64 bit and whatever lies beyond: with
    /// the Argon2id work factor the effective cost is above 80 bit.
    Excellent,
}

/// The bit thresholds of [`Level::Sufficient`], [`Level::Good`],
/// [`Level::VeryGood`] and [`Level::Excellent`], in that order. The
/// time estimates in the level docs assume about a thousand Argon2id
/// guesses per second per GPU with joy-crypt's parameters (64 MiB, t=3).
pub const THRESHOLDS: [f64; 4] = [28.0, 45.0, 60.0, CEILING];

/// Where the estimator stops counting: `log2(u64::MAX)`. A passphrase
/// at the ceiling is at least this strong; how much more is not known.
pub const CEILING: f64 = 64.0;

/// The one sentence a person confirms to keep an insufficient passphrase
/// (operator 2026-10-12): the CLI asks it with (y/N), the app shows it
/// as the checkbox under the meter.
pub const RISK_SENTENCE: &str = "I know and accept the risk.";

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
    /// `log2` of zxcvbn's guess estimate, at most [`CEILING`]. Zero for
    /// an empty passphrase.
    pub bits: f64,
    pub level: Level,
}

impl Strength {
    /// The words next to the bar, the same on every surface:
    /// `good (entropy 47 bit)`, or `excellent (entropy >64 bit)` at the
    /// ceiling. The longest possible text is
    /// `insufficient (entropy 27 bit)`.
    pub fn text(&self) -> String {
        if self.bits >= CEILING {
            format!("{} (entropy >{} bit)", self.level.label(), CEILING as u64)
        } else {
            format!(
                "{} (entropy {} bit)",
                self.level.label(),
                self.bits.round() as u64
            )
        }
    }

    /// Whether setting this passphrase takes the person's word for the
    /// risk: insufficient, and typed at all.
    pub fn needs_risk_acknowledgement(&self) -> bool {
        self.level == Level::Insufficient && self.bits > 0.0
    }
}

/// Judge a passphrase. Every surface calls this on every keystroke, so
/// it takes the text as it stands, empty included.
#[cfg(feature = "estimate")]
pub fn strength(passphrase: &str) -> Strength {
    if passphrase.is_empty() {
        return Strength {
            bits: 0.0,
            level: Level::Insufficient,
        };
    }
    let bits = zxcvbn::zxcvbn(passphrase, &[]).guesses_log10() * LOG2_10;
    Strength {
        bits,
        level: Level::of(bits),
    }
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
        assert_eq!(Level::of(63.99), Level::VeryGood);
        assert_eq!(Level::of(64.0), Level::Excellent);
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

    #[cfg(feature = "estimate")]
    #[test]
    fn known_inputs_land_where_the_decision_says() {
        assert_eq!(strength("q w e").level, Level::Insufficient);
        assert_eq!(strength("a a a").level, Level::Insufficient);
        assert_eq!(strength("password123").level, Level::Insufficient);
        assert_eq!(strength("qwerty").level, Level::Insufficient);
        assert_eq!(strength("Tr0ub4dor&3").level, Level::Sufficient);
        // zxcvbn counts ten guesses per character of random text:
        // fourteen are Good, nineteen VeryGood, twenty-five at the ceiling
        assert_eq!(strength("k7#Qz9!vLp2&Rm").level, Level::Good);
        assert_eq!(strength("k7#Qz9!vLp2&Rm8xW!c").level, Level::VeryGood);
        assert_eq!(
            strength("k7#Qz9!vLp2&Rm8xW!c4Nb@Yq").level,
            Level::Excellent
        );
        // four random words with their spaces are at the ceiling
        assert_eq!(
            strength("ladle quartz nimbus fjord").level,
            Level::Excellent
        );
        assert_eq!(strength("the quick brown fox").level, Level::Good);
    }

    /// The number is the crate's own and the same on every call; it ends
    /// at the ceiling instead of going on.
    #[cfg(feature = "estimate")]
    #[test]
    fn the_number_stops_at_the_ceiling_and_does_not_move_between_calls() {
        let long = "ladle quartz nimbus fjord carapace velvet orchid tundra";
        let first = strength(long);
        assert_eq!(first.bits, CEILING);
        assert_eq!(first.level, Level::Excellent);
        for _ in 0..20 {
            assert_eq!(strength(long).bits, first.bits);
        }
    }

    #[cfg(feature = "estimate")]
    #[test]
    fn the_text_names_the_level_and_the_bits_and_the_ceiling() {
        assert_eq!(strength("q w e").text(), "insufficient (entropy 17 bit)");
        assert_eq!(
            strength("ladle quartz nimbus fjord").text(),
            "excellent (entropy >64 bit)"
        );
        assert_eq!(strength("").text(), "insufficient (entropy 0 bit)");
        assert!(strength("q w e").needs_risk_acknowledgement());
        assert!(!strength("").needs_risk_acknowledgement());
        assert!(!strength("the quick brown fox").needs_risk_acknowledgement());
    }

    #[cfg(feature = "estimate")]
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
