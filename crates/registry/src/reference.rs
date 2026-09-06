//! Image reference parsing, docker-style:
//! `[host/]repo[:tag][@digest]` with the docker.io `library/` default.

use anyhow::{anyhow, Result};

const DEFAULT_REGISTRY: &str = "docker.io";
const OFFICIAL_REPO_PREFIX: &str = "library/";
const DEFAULT_TAG: &str = "latest";

#[derive(Debug, Clone, PartialEq)]
pub struct ImageRef {
    /// docker.io, ghcr.io, quay.io, registry.local:5000, ...
    pub registry: String,
    /// Fully qualified repo (library/busybox for official images).
    pub repo: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl ImageRef {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() {
            return Err(anyhow!("empty image reference"));
        }
        let (rest, digest) = match s.split_once('@') {
            Some((r, d)) => (r, Some(d.to_string())),
            None => (s, None),
        };
        if let Some(d) = &digest {
            if !d.starts_with("sha256:") {
                return Err(anyhow!("unsupported digest algorithm in {d}"));
            }
        }
        let (registry, path) = split_registry(rest);
        let (repo, tag) = split_tag(&path);
        if repo.is_empty() {
            return Err(anyhow!("invalid reference {input}: missing repository"));
        }
        let is_default = registry == DEFAULT_REGISTRY;
        let mut reference = ImageRef {
            registry,
            repo: normalize_repo(&repo, &is_default),
            tag,
            digest,
        };
        if reference.tag.is_none() && reference.digest.is_none() {
            reference.tag = Some(DEFAULT_TAG.into());
        }
        Ok(reference)
    }

    pub fn registry_is_default(&self) -> bool {
        self.registry == DEFAULT_REGISTRY
    }

    /// `busybox`, `user/app:1.0`, `registry:5000/x/y@sha256:...`
    pub fn display_ref(&self) -> String {
        let mut s = String::new();
        if !self.registry_is_default() {
            s.push_str(&self.registry);
            s.push('/');
        }
        let repo_display =
            if self.registry_is_default() && self.repo.starts_with(OFFICIAL_REPO_PREFIX) {
                &self.repo[OFFICIAL_REPO_PREFIX.len()..]
            } else {
                &self.repo
            };
        s.push_str(repo_display);
        if let Some(t) = &self.tag {
            s.push(':');
            s.push_str(t);
        }
        if let Some(d) = &self.digest {
            s.push('@');
            s.push_str(d);
        }
        s
    }

    /// Tag index key, or None when the reference names no tag. Digest-only
    /// references claim no tag: defaulting them to :latest would steal the
    /// tag from whatever the registry currently serves there.
    pub fn tag_key_opt(&self) -> Option<String> {
        self.tag
            .as_deref()
            .map(|t| format!("{}:{t}", self.display_ref_no_tag()))
    }

    /// Canonical `repo:tag` (docker tag format) used in the tag index.
    pub fn tag_key(&self) -> String {
        self.tag_key_opt()
            .unwrap_or_else(|| format!("{}:{DEFAULT_TAG}", self.display_ref_no_tag()))
    }

    /// Repository path used in registry API URLs: `/v2/<repo>/...`.
    pub fn api_repo(&self) -> &str {
        &self.repo
    }
}

fn registry_is_default_host(host: &str) -> bool {
    host == DEFAULT_REGISTRY || host == "index.docker.io" || host == "registry-1.docker.io"
}

fn split_registry(rest: &str) -> (String, String) {
    // A host is present iff the first segment contains '.', ':' or is
    // "localhost" (docker's rule).
    let first = rest.split('/').next().unwrap_or("");
    let looks_like_host = first.contains('.') || first.contains(':') || first == "localhost";
    if looks_like_host && rest.contains('/') {
        let (host, path) = rest.split_once('/').unwrap();
        let host = if registry_is_default_host(host) {
            DEFAULT_REGISTRY.into()
        } else {
            host.into()
        };
        (host, path.to_string())
    } else if looks_like_host && !rest.contains('/') {
        // e.g. "busybox:latest" — that's a tag, not a host.
        (DEFAULT_REGISTRY.into(), rest.to_string())
    } else {
        (DEFAULT_REGISTRY.into(), rest.to_string())
    }
}

fn normalize_repo(repo: &str, default_registry: &bool) -> String {
    if *default_registry && !repo.contains('/') {
        format!("{OFFICIAL_REPO_PREFIX}{repo}")
    } else {
        repo.to_string()
    }
}

fn split_tag(path: &str) -> (String, Option<String>) {
    // Tag is only in the last path segment, after the last ':'.
    let (repo, tag) = match path.rsplit_once(':') {
        Some((r, t)) if !t.contains('/') => (r, Some(t.to_string())),
        _ => (path, None),
    };
    (repo.to_string(), tag)
}

impl ImageRef {
    /// Repo without tag, e.g. `busybox` / `ghcr.io/owner/img` (for RepoDigests).
    pub fn display_ref_no_tag(&self) -> String {
        let mut s = String::new();
        if !self.registry_is_default() {
            s.push_str(&self.registry);
            s.push('/');
        }
        if self.registry_is_default() && self.repo.starts_with(OFFICIAL_REPO_PREFIX) {
            s.push_str(&self.repo[OFFICIAL_REPO_PREFIX.len()..]);
        } else {
            s.push_str(&self.repo);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_image() {
        let r = ImageRef::parse("busybox").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repo, "library/busybox");
        assert_eq!(r.tag.as_deref(), Some("latest"));
        assert_eq!(r.tag_key(), "busybox:latest");
        assert_eq!(r.display_ref(), "busybox:latest");
    }

    #[test]
    fn official_image_versioned() {
        let r = ImageRef::parse("alpine:3.19").unwrap();
        assert_eq!(r.repo, "library/alpine");
        assert_eq!(r.tag.as_deref(), Some("3.19"));
    }

    #[test]
    fn user_repo() {
        let r = ImageRef::parse("myuser/myapp:v2").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repo, "myuser/myapp");
        assert_eq!(r.tag.as_deref(), Some("v2"));
    }

    #[test]
    fn custom_registry_with_port() {
        let r = ImageRef::parse("registry.local:5000/team/app:dev").unwrap();
        assert_eq!(r.registry, "registry.local:5000");
        assert_eq!(r.repo, "team/app");
        assert_eq!(r.tag.as_deref(), Some("dev"));
    }

    #[test]
    fn port_and_tag_disambiguation() {
        // "busybox:latest" is repo:tag, not a host
        let r = ImageRef::parse("busybox:latest").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.tag.as_deref(), Some("latest"));
    }

    #[test]
    fn digest_ref() {
        let r = ImageRef::parse(
            "busybox@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert!(r.digest.as_deref().unwrap().starts_with("sha256:"));
        assert_eq!(r.repo, "library/busybox");
    }

    #[test]
    fn digest_only_claims_no_tag() {
        let r = ImageRef::parse(
            "busybox@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(r.tag, None);
        assert_eq!(r.tag_key_opt(), None);
        // tag_key keeps its legacy :latest default for callers that need a key.
        assert_eq!(r.tag_key(), "busybox:latest");
    }

    #[test]
    fn ghcr() {
        let r = ImageRef::parse("ghcr.io/owner/img:1.0").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repo, "owner/img");
    }
}
