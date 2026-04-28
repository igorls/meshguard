//! Single source of truth for meshguard version.
//!
//! Release process:
//!   1. Bump `version` here
//!   2. Update CHANGELOG.md with the new section
//!   3. Commit: "release: vX.Y.Z"
//!   4. Tag:    git tag vX.Y.Z
//!   5. Push:   git push && git push --tags
//!
//! The release.yml workflow validates that the tag matches this constant.

pub const version = "0.9.0";

/// Semantic version components for programmatic comparison.
pub const major: u16 = 0;
pub const minor: u16 = 9;
pub const patch: u16 = 0;
