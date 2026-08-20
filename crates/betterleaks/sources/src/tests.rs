//! Characterization tests for the `sources` core. Go's `source.go`,
//! `fragment.go` and `attribute.go` have NO test file, so these pin the
//! behaviour read off the source.

use super::*;

/// Go's `Attr` returns "" for a missing key AND for a nil map — never an error,
/// never a panic. That total-function behaviour is what `report::Finding::attr`
/// leans on for its deprecated-field fallback.
#[test]
fn attr_missing_key_is_empty() {
    let f = Fragment::default();
    assert_eq!(f.attr(ATTR_PATH), "");
    assert_eq!(f.attr("nonexistent"), "");
}

/// Go lazily allocates `Attributes` on first `SetAttr`; the port starts with an
/// empty map. Observationally identical.
#[test]
fn set_attr_then_read() {
    let mut f = Fragment::default();
    assert!(f.attributes.is_empty());
    f.set_attr(ATTR_PATH, "a/b.go");
    f.set_attr(ATTR_GIT_SHA, "deadbeef");
    assert_eq!(f.attr(ATTR_PATH), "a/b.go");
    assert_eq!(f.attr(ATTR_GIT_SHA), "deadbeef");
    assert_eq!(f.attributes.len(), 2);
}

/// Writing the same key twice overwrites (Go map assignment).
#[test]
fn set_attr_overwrites() {
    let mut f = Fragment::default();
    f.set_attr(ATTR_PATH, "first");
    f.set_attr(ATTR_PATH, "second");
    assert_eq!(f.attr(ATTR_PATH), "second");
    assert_eq!(f.attributes.len(), 1);
}

/// The reshape: attribute iteration is DETERMINISTIC here, where Go's map order
/// is randomized. Pinned so the divergence is visible if anyone swaps the map.
#[test]
fn attributes_iterate_in_sorted_order() {
    let mut f = Fragment::default();
    f.set_attr(ATTR_URL, "u");
    f.set_attr(ATTR_PATH, "p");
    f.set_attr(ATTR_GIT_SHA, "s");
    let keys: Vec<&str> = f.attributes.keys().map(|k| k.as_str()).collect();
    assert_eq!(keys, vec!["git.sha", "path", "url"]);
}

/// The zero value is usable, matching Go's `Fragment{}`.
#[test]
fn zero_fragment_is_usable() {
    let f = Fragment::default();
    assert_eq!(f.raw, "");
    assert!(f.bytes.is_empty());
    assert!(!f.inherited_from_finding);
    assert_eq!(f.start_line, 0);
}

/// The attribute strings are a WIRE CONTRACT — they land verbatim in
/// `Finding.Attributes` JSON and are matched by name in filter expressions.
/// Spot-check one from each family against the Go source.
#[test]
fn attribute_keys_match_go_verbatim() {
    assert_eq!(ATTR_PATH, "path");
    assert_eq!(ATTR_URL, "url");
    assert_eq!(ATTR_RESOURCE, "resource");
    assert_eq!(ATTR_GIT_SHA, "git.sha");
    assert_eq!(ATTR_GIT_AUTHOR_EMAIL, "git.author_email");
    assert_eq!(ATTR_FS_SYMLINK, "fs.symlink");
    assert_eq!(ATTR_GITHUB_ISSUE_NUMBER, "github.issue.number");
    assert_eq!(ATTR_GITLAB_CI_PIPELINE_ID, "gitlab.ci_pipeline.id");
    assert_eq!(ATTR_HUGGINGFACE_BUCKET_XET_HASH, "huggingface.bucket.xet_hash");
    assert_eq!(ATTR_S3_STORAGE_CLASS, "s3.storage_class");
}

#[test]
fn resource_values_match_go_verbatim() {
    assert_eq!(RESOURCE_FILE_CONTENT, "fs.content");
    assert_eq!(RESOURCE_GIT_PATCH_CONTENT, "git.patch_content");
    assert_eq!(RESOURCE_GITHUB_RELEASE_ASSET, "github.release_asset");
    assert_eq!(RESOURCE_GITLAB_CI_ARTIFACT, "gitlab.ci_artifact");
    assert_eq!(RESOURCE_HUGGINGFACE_REPO, "huggingface.repository");
    assert_eq!(RESOURCE_S3_OBJECT, "s3.object");
}

/// `file.go:22`. An archive fragment's path is `outer!inner`.
#[test]
fn inner_path_separator() {
    assert_eq!(INNER_PATH_SEPARATOR, "!");
    let p = format!("a.zip{INNER_PATH_SEPARATOR}inner/b.txt");
    assert_eq!(p, "a.zip!inner/b.txt");
}

/// `SkipFunc`'s contract is "true means SKIP" — the inverted sense is easy to
/// get backwards, so pin it.
#[test]
fn skip_func_true_means_skip() {
    let skip_vendored: SkipFunc = &|attrs: &BTreeMap<String, String>| {
        attrs.get(ATTR_PATH).is_some_and(|p| p.starts_with("vendor/"))
    };
    let mut vendored = Fragment::default();
    vendored.set_attr(ATTR_PATH, "vendor/x.go");
    let mut own = Fragment::default();
    own.set_attr(ATTR_PATH, "src/x.go");

    assert!(skip_vendored(&vendored.attributes), "vendored should be skipped");
    assert!(!skip_vendored(&own.attributes), "own source should be kept");
}

/// The `Source` trait is object-usable and the yield callback can stop early by
/// returning an error, mirroring Go's `FragmentsFunc` error return.
#[test]
fn source_yields_fragments() {
    struct TwoFragments;
    impl Source for TwoFragments {
        type Error = String;
        fn fragments(&self, yield_fn: FragmentsFunc<'_, String>) -> Result<(), String> {
            for i in 0..2 {
                let mut f = Fragment {
                    raw: format!("content {i}"),
                    start_line: i + 1,
                    ..Default::default()
                };
                f.set_attr(ATTR_PATH, &format!("f{i}.txt"));
                yield_fn(Ok(f))?;
            }
            Ok(())
        }
    }

    let mut seen = Vec::new();
    let mut collect = |r: Result<Fragment, String>| -> Result<(), String> {
        seen.push(r?);
        Ok(())
    };
    TwoFragments.fragments(&mut collect).expect("no error");

    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].raw, "content 0");
    assert_eq!(seen[0].attr(ATTR_PATH), "f0.txt");
    assert_eq!(seen[1].start_line, 2);
}

/// An error returned by the yield callback aborts the walk — Go's
/// `FragmentsFunc` returning non-nil stops `Fragments`.
#[test]
fn yield_error_aborts_the_walk() {
    struct Many;
    impl Source for Many {
        type Error = String;
        fn fragments(&self, yield_fn: FragmentsFunc<'_, String>) -> Result<(), String> {
            for i in 0..100 {
                yield_fn(Ok(Fragment { start_line: i, ..Default::default() }))?;
            }
            Ok(())
        }
    }

    let mut count = 0;
    let mut stop_after_three = |r: Result<Fragment, String>| -> Result<(), String> {
        let _ = r?;
        count += 1;
        if count == 3 {
            return Err("stop".to_string());
        }
        Ok(())
    };
    let err = Many.fragments(&mut stop_after_three).unwrap_err();
    assert_eq!(err, "stop");
    assert_eq!(count, 3, "the walk must abort, not run to completion");
}
