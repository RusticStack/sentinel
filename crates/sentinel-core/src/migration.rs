//! Guided migration's writes: the three permissions the one App needs beyond its base set to
//! change a repository's workflows. Contents write commits to the `sentinel/migrate` branch,
//! pull requests write opens and updates the pull request, and workflows write is GitHub's
//! separate grant for a commit that touches `.github/workflows/`. They are the same three in an
//! organization's and a personal namespace's installation, which is what lets a person migrate
//! their own repositories ([plan 16.5](../../../plan.md#165-guided-github-actions-migration)).

/// What a migration writes with, as a bitset so an installation snapshot carries it in one
/// column and a write path reads it in one statement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MigrationPermissions(u8);

impl MigrationPermissions {
    /// Bit 0: contents write. Bit 1: pull requests write. Bit 2: workflows write.
    const CONTENTS: u8 = 0b001;
    const PULL_REQUESTS: u8 = 0b010;
    const WORKFLOWS: u8 = 0b100;

    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self(0b111);

    /// The bits an installation snapshot states, or `None` for bits this build does not know.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn grants(contents: bool, pull_requests: bool, workflows: bool) -> Self {
        let mut bits = 0;
        if contents {
            bits |= Self::CONTENTS;
        }
        if pull_requests {
            bits |= Self::PULL_REQUESTS;
        }
        if workflows {
            bits |= Self::WORKFLOWS;
        }
        Self(bits)
    }

    /// What is missing, named as GitHub's App settings name them and in one fixed order; empty
    /// when all three are granted.
    pub const fn missing(self) -> &'static [&'static str] {
        const NONE: &[&str] = &[];
        const CONTENTS: &[&str] = &["contents"];
        const PULL_REQUESTS: &[&str] = &["pull_requests"];
        const WORKFLOWS: &[&str] = &["workflows"];
        const CONTENTS_PULL_REQUESTS: &[&str] = &["contents", "pull_requests"];
        const CONTENTS_WORKFLOWS: &[&str] = &["contents", "workflows"];
        const PULL_REQUESTS_WORKFLOWS: &[&str] = &["pull_requests", "workflows"];
        const ALL: &[&str] = &["contents", "pull_requests", "workflows"];
        match self.0 {
            0b111 => NONE,
            0b110 => CONTENTS,
            0b101 => PULL_REQUESTS,
            0b100 => CONTENTS_PULL_REQUESTS,
            0b011 => WORKFLOWS,
            0b010 => CONTENTS_WORKFLOWS,
            0b001 => PULL_REQUESTS_WORKFLOWS,
            _ => ALL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_missing_writes_are_named_as_the_app_settings_name_them() {
        assert!(MigrationPermissions::ALL.missing().is_empty());
        assert_eq!(
            MigrationPermissions::NONE.missing(),
            ["contents", "pull_requests", "workflows"]
        );
        assert_eq!(
            MigrationPermissions::grants(true, true, false).missing(),
            ["workflows"]
        );
        assert_eq!(
            MigrationPermissions::grants(false, true, true).missing(),
            ["contents"]
        );
        assert_eq!(
            MigrationPermissions::grants(true, false, true).missing(),
            ["pull_requests"]
        );
        assert_eq!(
            MigrationPermissions::grants(false, false, true).missing(),
            ["contents", "pull_requests"]
        );
        assert_eq!(MigrationPermissions::from_bits(8), None);
        assert_eq!(
            MigrationPermissions::from_bits(7),
            Some(MigrationPermissions::ALL)
        );
        assert!(MigrationPermissions::ALL.contains(MigrationPermissions::ALL));
        assert!(
            !MigrationPermissions::grants(true, true, false).contains(MigrationPermissions::ALL)
        );
    }
}
