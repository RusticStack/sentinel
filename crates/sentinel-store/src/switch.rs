//! A tenant's feature switch: what turning one on or off did. Runner mode and guided migration
//! answer the same four ways, and the routes that set them answer the same errors.

/// What turning a tenant's switch asked for did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Switch {
    /// The tenant now reads what was asked for, and the change is audited.
    Set,
    /// It already read that; nothing changed and nothing was written.
    Unchanged,
    /// Refused: the App's live installations do not grant these, named as GitHub's App settings
    /// name them.
    Missing(Vec<&'static str>),
    /// Refused: the tenant has no live GitHub installation to act through.
    NoInstallation,
    /// Refused: the tenant's runner-mode switch is off, so it serves no runner jobs at all and a
    /// setting that only feeds them would be one nobody reads.
    NoRunnerMode,
}
