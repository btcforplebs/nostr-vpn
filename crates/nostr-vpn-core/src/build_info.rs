//! Which source a binary was built from. Two builds of the same release both
//! report its version (a web panel and a daemon from different images both
//! said 4.1.18), so a build that knows its commit appends it.

/// `version` with `+<commit>` appended when the build set `NVPN_BUILD_COMMIT`
/// to a commit hash, for example `4.1.18+0c1f0d94a6f7ba1b844ec358142d7f7bedd48b77`.
/// Builds that do not set it (the desktop and mobile apps) get `version`
/// unchanged, so their update and service-version checks see what they did
/// before.
#[must_use]
pub fn version_with_build_commit(version: &str) -> String {
    with_commit(version, option_env!("NVPN_BUILD_COMMIT"))
}

fn with_commit(version: &str, commit: Option<&str>) -> String {
    match commit.map(str::trim) {
        Some(commit)
            if (7..=40).contains(&commit.len())
                && commit.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            format!("{version}+{}", commit.to_ascii_lowercase())
        }
        _ => version.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::with_commit;

    #[test]
    fn appends_a_commit_hash_and_ignores_anything_else() {
        let sha = "0c1f0d94a6f7ba1b844ec358142d7f7bedd48b77";
        assert_eq!(with_commit("4.1.18", Some(sha)), format!("4.1.18+{sha}"));
        assert_eq!(with_commit("4.1.18", Some("0C1F0D9")), "4.1.18+0c1f0d9");
        for unusable in [
            None,
            Some(""),
            Some("main"),
            Some("0c1f0d"),
            Some("g1f0d94a"),
        ] {
            assert_eq!(with_commit("4.1.18", unusable), "4.1.18", "{unusable:?}");
        }
    }
}
