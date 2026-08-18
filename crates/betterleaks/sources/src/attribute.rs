//! Port of Go `sources/attribute.go` — the attribute-key and resource-value
//! constants every source stamps onto a [`Fragment`](crate::Fragment).
//!
//! Go's source carries `// TODO move to a separate package (attrkeys/) once
//! stable`; the port keeps them in one module so that move stays a one-liner.
//!
//! These strings are a WIRE CONTRACT — they appear verbatim as JSON keys in
//! `Finding.Attributes` and are matched by name in filter expressions, so every
//! value here is byte-for-byte Go's.

// ── Universal ───────────────────────────────────────────────────────────────
pub const ATTR_PATH: &str = "path";
pub const ATTR_URL: &str = "url";

// ── Resource key ────────────────────────────────────────────────────────────
pub const ATTR_RESOURCE: &str = "resource";

// ── Resource values — what kind of thing the fragment is ────────────────────
pub const RESOURCE_FILE_CONTENT: &str = "fs.content";
pub const RESOURCE_GIT_PATCH_CONTENT: &str = "git.patch_content";
pub const RESOURCE_GITHUB_REPO: &str = "github.repository";
pub const RESOURCE_GITHUB_ISSUE: &str = "github.issue";
pub const RESOURCE_GITHUB_PR: &str = "github.pr";
pub const RESOURCE_GITHUB_COMMENT: &str = "github.comment";
pub const RESOURCE_GITHUB_ACTIONS: &str = "github.actions";
pub const RESOURCE_GITHUB_DISCUSSION: &str = "github.discussion";
pub const RESOURCE_GITHUB_RELEASE: &str = "github.release";
pub const RESOURCE_GITHUB_RELEASE_ASSET: &str = "github.release_asset";
pub const RESOURCE_GITHUB_GIST: &str = "github.gist";

pub const RESOURCE_GITLAB_PROJECT: &str = "gitlab.project";
pub const RESOURCE_GITLAB_ISSUE: &str = "gitlab.issue";
pub const RESOURCE_GITLAB_MR: &str = "gitlab.mr";
pub const RESOURCE_GITLAB_COMMENT: &str = "gitlab.comment";
pub const RESOURCE_GITLAB_SNIPPET: &str = "gitlab.snippet";
pub const RESOURCE_GITLAB_RELEASE: &str = "gitlab.release";
pub const RESOURCE_GITLAB_RELEASE_ASSET: &str = "gitlab.release_asset";
pub const RESOURCE_GITLAB_CI_JOB: &str = "gitlab.ci_job";
pub const RESOURCE_GITLAB_CI_ARTIFACT: &str = "gitlab.ci_artifact";

pub const RESOURCE_HUGGINGFACE_REPO: &str = "huggingface.repository";
pub const RESOURCE_HUGGINGFACE_DISCUSSION: &str = "huggingface.discussion";
pub const RESOURCE_HUGGINGFACE_PR: &str = "huggingface.pr";
pub const RESOURCE_HUGGINGFACE_COMMENT: &str = "huggingface.comment";
pub const RESOURCE_HUGGINGFACE_BUCKET: &str = "huggingface.bucket";

// ── Git ─────────────────────────────────────────────────────────────────────
pub const ATTR_GIT_SHA: &str = "git.sha";
pub const ATTR_GIT_AUTHOR_NAME: &str = "git.author_name";
pub const ATTR_GIT_AUTHOR_EMAIL: &str = "git.author_email";
pub const ATTR_GIT_DATE: &str = "git.date";
pub const ATTR_GIT_MESSAGE: &str = "git.message";
pub const ATTR_GIT_REMOTE_URL: &str = "git.remote_url";
pub const ATTR_GIT_PLATFORM: &str = "git.platform";

// ── Filesystem ──────────────────────────────────────────────────────────────
pub const ATTR_FS_SYMLINK: &str = "fs.symlink";

// ── GitHub ──────────────────────────────────────────────────────────────────
pub const ATTR_GITHUB_OWNER: &str = "github.owner";
pub const ATTR_GITHUB_OWNER_TYPE: &str = "github.owner_type";
pub const ATTR_GITHUB_REPO: &str = "github.repo";
pub const ATTR_GITHUB_REPO_URL: &str = "github.repo_url";
pub const ATTR_GITHUB_VISIBILITY: &str = "github.visibility";
pub const ATTR_GITHUB_ISSUE_NUMBER: &str = "github.issue.number";
pub const ATTR_GITHUB_PR_NUMBER: &str = "github.pr.number";
pub const ATTR_GITHUB_COMMENT_ID: &str = "github.comment.id";

pub const ATTR_GITHUB_ACTIONS_RUN_ID: &str = "github.actions.run_id";
pub const ATTR_GITHUB_ACTIONS_RUN_NAME: &str = "github.actions.run_name";
pub const ATTR_GITHUB_ACTIONS_RUN_URL: &str = "github.actions.run_url";
pub const ATTR_GITHUB_ACTIONS_EVENT: &str = "github.actions.event";

pub const ATTR_GITHUB_DISCUSSION_NUMBER: &str = "github.discussion.number";
pub const ATTR_GITHUB_RELEASE_TAG: &str = "github.release.tag";
pub const ATTR_GITHUB_RELEASE_ASSET_NAME: &str = "github.release.asset_name";
pub const ATTR_GITHUB_GIST_ID: &str = "github.gist.id";
pub const ATTR_GITHUB_GIST_FILENAME: &str = "github.gist.filename";
pub const ATTR_GITHUB_GIST_OWNER: &str = "github.gist.owner";

// ── GitLab ──────────────────────────────────────────────────────────────────
pub const ATTR_GITLAB_PROJECT_ID: &str = "gitlab.project.id";
pub const ATTR_GITLAB_PROJECT_PATH: &str = "gitlab.project.path";
pub const ATTR_GITLAB_PROJECT_URL: &str = "gitlab.project.url";
pub const ATTR_GITLAB_VISIBILITY: &str = "gitlab.visibility";
pub const ATTR_GITLAB_NAMESPACE: &str = "gitlab.namespace";
pub const ATTR_GITLAB_ISSUE_IID: &str = "gitlab.issue.iid";
pub const ATTR_GITLAB_MR_IID: &str = "gitlab.mr.iid";
pub const ATTR_GITLAB_COMMENT_ID: &str = "gitlab.comment.id";
pub const ATTR_GITLAB_SNIPPET_ID: &str = "gitlab.snippet.id";
pub const ATTR_GITLAB_SNIPPET_FILENAME: &str = "gitlab.snippet.filename";
pub const ATTR_GITLAB_RELEASE_TAG: &str = "gitlab.release.tag";
pub const ATTR_GITLAB_RELEASE_ASSET_NAME: &str = "gitlab.release.asset_name";
pub const ATTR_GITLAB_CI_JOB_ID: &str = "gitlab.ci_job.id";
pub const ATTR_GITLAB_CI_JOB_NAME: &str = "gitlab.ci_job.name";
pub const ATTR_GITLAB_CI_PIPELINE_ID: &str = "gitlab.ci_pipeline.id";

// ── Hugging Face ────────────────────────────────────────────────────────────
pub const ATTR_HUGGINGFACE_OWNER: &str = "huggingface.owner";
pub const ATTR_HUGGINGFACE_REPO: &str = "huggingface.repo";
pub const ATTR_HUGGINGFACE_REPO_TYPE: &str = "huggingface.repo_type";
pub const ATTR_HUGGINGFACE_REPO_URL: &str = "huggingface.repo_url";
pub const ATTR_HUGGINGFACE_VISIBILITY: &str = "huggingface.visibility";
pub const ATTR_HUGGINGFACE_DISCUSSION_NUMBER: &str = "huggingface.discussion.number";
pub const ATTR_HUGGINGFACE_COMMENT_ID: &str = "huggingface.comment.id";
pub const ATTR_HUGGINGFACE_AUTHOR: &str = "huggingface.author";
pub const ATTR_HUGGINGFACE_COMMUNITY_RESOURCE: &str = "huggingface.community.resource";
pub const ATTR_HUGGINGFACE_BUCKET: &str = "huggingface.bucket";
pub const ATTR_HUGGINGFACE_BUCKET_URL: &str = "huggingface.bucket_url";
pub const ATTR_HUGGINGFACE_BUCKET_PATH: &str = "huggingface.bucket.path";
pub const ATTR_HUGGINGFACE_BUCKET_SIZE: &str = "huggingface.bucket.size";
pub const ATTR_HUGGINGFACE_BUCKET_MTIME: &str = "huggingface.bucket.mtime";
pub const ATTR_HUGGINGFACE_BUCKET_XET_HASH: &str = "huggingface.bucket.xet_hash";

// ── S3 (and S3-compatible object stores) ────────────────────────────────────
pub const ATTR_S3_BUCKET: &str = "s3.bucket";
pub const ATTR_S3_KEY: &str = "s3.key";
pub const ATTR_S3_REGION: &str = "s3.region";
pub const ATTR_S3_ENDPOINT: &str = "s3.endpoint";
pub const ATTR_S3_LAST_MODIFIED: &str = "s3.last_modified";
pub const ATTR_S3_ETAG: &str = "s3.etag";
pub const ATTR_S3_SIZE: &str = "s3.size";
pub const ATTR_S3_STORAGE_CLASS: &str = "s3.storage_class";

pub const RESOURCE_S3_OBJECT: &str = "s3.object";
