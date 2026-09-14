//! One file-path/ref-segment glob, shared by `hash_files` patterns and source
//! policies so a repository learns one wildcard rule.
//!
//! `*` matches any run of characters inside one segment; segments themselves
//! are separated by `/`. `**` is a whole-segment wildcard handled by callers
//! that walk segments ([`crate::policy::pattern_matches`] for refs,
//! `hash_files` for directory trees).

/// An iterative, linear-time match of one glob segment against one name.
pub(crate) fn segment(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.as_bytes(), name.as_bytes());
    let (mut pi, mut ni) = (0, 0);
    let mut star = None;
    while ni < n.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ni));
            pi += 1;
        } else if pi < p.len() && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}
