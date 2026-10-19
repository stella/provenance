use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::Path,
};

use miette::Diagnostic;
use serde_json::Value;

pub(crate) type PackageIdentity = (String, String);

#[derive(Debug)]
pub(crate) enum JavascriptClosureError {
    MissingLockfile {
        path: String,
    },
    UnsupportedLockfile {
        path: String,
        reason: String,
    },
    Read {
        path: String,
        source: std::io::Error,
    },
    Parse {
        path: String,
        reason: String,
    },
    Unresolved {
        parent: String,
        name: String,
    },
    MissingComponents {
        packages: String,
    },
}

impl std::fmt::Display for JavascriptClosureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingLockfile { path } => write!(
                f,
                "JavaScript project at {path} has no supported lockfile (expected bun.lock or package-lock.json v3)"
            ),
            Self::UnsupportedLockfile { path, reason } => {
                write!(f, "unsupported JavaScript lockfile at {path}: {reason}")
            }
            Self::Read { path, source } => write!(
                f,
                "failed to read JavaScript dependency input {path}: {source}"
            ),
            Self::Parse { path, reason } => write!(
                f,
                "failed to parse JavaScript dependency input {path}: {reason}"
            ),
            Self::Unresolved { parent, name } => write!(
                f,
                "lockfile does not resolve production dependency {name} requested by {parent}"
            ),
            Self::MissingComponents { packages } => write!(
                f,
                "generated SBOM is missing production dependencies: {packages}"
            ),
        }
    }
}

impl std::error::Error for JavascriptClosureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Diagnostic for JavascriptClosureError {}

#[derive(Clone, Debug)]
struct LockedPackage {
    identity: PackageIdentity,
    dependencies: BTreeMap<String, String>,
    os: Vec<String>,
    cpu: Vec<String>,
}

#[derive(Debug)]
struct LockGraph {
    roots: BTreeMap<String, String>,
    packages: BTreeMap<String, LockedPackage>,
}

pub(crate) fn production_closure(
    project_dir: &Path,
) -> Result<BTreeSet<PackageIdentity>, JavascriptClosureError> {
    let bun = project_dir.join("bun.lock");
    if bun.is_file() {
        return bun_closure(&bun);
    }
    let npm = project_dir.join("package-lock.json");
    if npm.is_file() {
        return package_lock_closure(&npm);
    }
    Err(JavascriptClosureError::MissingLockfile {
        path: project_dir.display().to_string(),
    })
}

fn read_json(path: &Path, jsonc: bool) -> Result<Value, JavascriptClosureError> {
    let raw = fs::read_to_string(path).map_err(|source| JavascriptClosureError::Read {
        path: path.display().to_string(),
        source,
    })?;
    if jsonc {
        serde_json::from_str(&strip_jsonc(&raw)).map_err(|error| JavascriptClosureError::Parse {
            path: path.display().to_string(),
            reason: error.to_string(),
        })
    } else {
        serde_json::from_str(&raw).map_err(|error| JavascriptClosureError::Parse {
            path: path.display().to_string(),
            reason: error.to_string(),
        })
    }
}

fn strip_jsonc(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut quoted = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if quoted {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            output.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for comment in chars.by_ref() {
                if comment == '\n' {
                    output.push('\n');
                    break;
                }
            }
        } else {
            output.push(ch);
        }
    }
    let chars = output.chars().collect::<Vec<_>>();
    let mut cleaned = String::with_capacity(output.len());
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in chars.iter().copied().enumerate() {
        if quoted {
            cleaned.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        if ch == '"' {
            quoted = true;
            cleaned.push(ch);
            continue;
        }
        if ch == ','
            && chars[index + 1..]
                .iter()
                .find(|next| !next.is_whitespace())
                .is_some_and(|next| matches!(next, '}' | ']'))
        {
            continue;
        }
        cleaned.push(ch);
    }
    cleaned
}

fn bun_closure(path: &Path) -> Result<BTreeSet<PackageIdentity>, JavascriptClosureError> {
    let value = read_json(path, true)?;
    let workspaces = value
        .get("workspaces")
        .and_then(Value::as_object)
        .ok_or_else(|| JavascriptClosureError::UnsupportedLockfile {
            path: path.display().to_string(),
            reason: String::from("missing workspaces table"),
        })?;
    let mut roots = BTreeMap::new();
    for workspace in workspaces.values().filter_map(Value::as_object) {
        for section in ["dependencies", "optionalDependencies", "peerDependencies"] {
            roots.extend(
                dependency_map(workspace, section)
                    .into_iter()
                    .filter(|(_, spec)| !spec.starts_with("workspace:")),
            );
        }
    }

    let packages = value
        .get("packages")
        .and_then(Value::as_object)
        .ok_or_else(|| JavascriptClosureError::UnsupportedLockfile {
            path: path.display().to_string(),
            reason: String::from("missing packages table"),
        })?;
    let mut graph = BTreeMap::new();
    for (key, entry) in packages {
        let Some(items) = entry.as_array() else {
            continue;
        };
        let Some(resolution) = items.first().and_then(Value::as_str) else {
            continue;
        };
        let Some(identity) = parse_bun_resolution(resolution) else {
            continue;
        };
        let metadata = items.get(2).and_then(Value::as_object);
        let mut dependencies = metadata
            .map(|m| dependency_map(m, "dependencies"))
            .unwrap_or_default();
        if let Some(m) = metadata {
            dependencies.extend(dependency_map(m, "optionalDependencies"));
            dependencies.extend(dependency_map(m, "peerDependencies"));
        }
        graph.insert(
            key.clone(),
            LockedPackage {
                identity,
                dependencies,
                os: metadata
                    .map(|m| string_list(m.get("os")))
                    .unwrap_or_default(),
                cpu: metadata
                    .map(|m| string_list(m.get("cpu")))
                    .unwrap_or_default(),
            },
        );
    }
    walk(LockGraph {
        roots,
        packages: graph,
    })
}

fn package_lock_closure(path: &Path) -> Result<BTreeSet<PackageIdentity>, JavascriptClosureError> {
    let value = read_json(path, false)?;
    if value.get("lockfileVersion").and_then(Value::as_u64) != Some(3) {
        return Err(JavascriptClosureError::UnsupportedLockfile {
            path: path.display().to_string(),
            reason: String::from("only package-lock.json v3 is supported"),
        });
    }
    let packages = value
        .get("packages")
        .and_then(Value::as_object)
        .ok_or_else(|| JavascriptClosureError::UnsupportedLockfile {
            path: path.display().to_string(),
            reason: String::from("missing packages table"),
        })?;
    let root = packages.get("").and_then(Value::as_object).ok_or_else(|| {
        JavascriptClosureError::UnsupportedLockfile {
            path: path.display().to_string(),
            reason: String::from("missing root package"),
        }
    })?;
    let mut roots = dependency_map(root, "dependencies");
    roots.extend(dependency_map(root, "optionalDependencies"));
    roots.extend(dependency_map(root, "peerDependencies"));
    let mut graph = BTreeMap::new();
    for (location, entry) in packages {
        if location.is_empty() {
            continue;
        }
        let Some(object) = entry.as_object() else {
            continue;
        };
        let Some(version) = object.get("version").and_then(Value::as_str) else {
            continue;
        };
        let Some(name) = package_name_from_location(location) else {
            continue;
        };
        let mut dependencies = dependency_map(object, "dependencies");
        dependencies.extend(dependency_map(object, "optionalDependencies"));
        dependencies.extend(dependency_map(object, "peerDependencies"));
        graph.insert(
            location.clone(),
            LockedPackage {
                identity: (name, version.to_string()),
                dependencies,
                os: string_list(object.get("os")),
                cpu: string_list(object.get("cpu")),
            },
        );
    }
    walk(LockGraph {
        roots,
        packages: graph,
    })
}

fn walk(graph: LockGraph) -> Result<BTreeSet<PackageIdentity>, JavascriptClosureError> {
    let mut closure = BTreeSet::new();
    let mut queue = graph
        .roots
        .into_iter()
        .map(|(name, spec)| (String::from("package.json"), name, spec))
        .collect::<VecDeque<_>>();
    let mut visited = BTreeSet::new();
    while let Some((parent, name, spec)) = queue.pop_front() {
        if is_node_builtin(&name) {
            continue;
        }
        let Some((key, package)) = resolve_locked(&graph.packages, &name, &spec, &parent) else {
            return Err(JavascriptClosureError::Unresolved { parent, name });
        };
        if !visited.insert(key.clone()) || !platform_matches(package) {
            continue;
        }
        closure.insert(package.identity.clone());
        for (child, child_spec) in &package.dependencies {
            queue.push_back((key.clone(), child.clone(), child_spec.clone()));
        }
    }
    Ok(closure)
}

fn resolve_locked<'a>(
    packages: &'a BTreeMap<String, LockedPackage>,
    name: &str,
    spec: &str,
    parent: &str,
) -> Option<(String, &'a LockedPackage)> {
    let candidates = [
        format!("{name}@{spec}"),
        name.to_string(),
        format!("node_modules/{name}"),
        format!("{parent}/node_modules/{name}"),
    ];
    candidates
        .into_iter()
        .find_map(|key| packages.get(&key).map(|package| (key, package)))
        .or_else(|| {
            let mut matches = packages
                .iter()
                .filter(|(_, package)| package.identity.0 == name);
            let first = matches.next()?;
            matches.next().is_none().then(|| (first.0.clone(), first.1))
        })
}

fn dependency_map(object: &serde_json::Map<String, Value>, key: &str) -> BTreeMap<String, String> {
    object
        .get(key)
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, spec)| Some((name.clone(), spec.as_str()?.to_string())))
        .collect()
}

fn parse_bun_resolution(resolution: &str) -> Option<PackageIdentity> {
    let value = resolution.strip_prefix("npm:").unwrap_or(resolution);
    if value.contains("@workspace:") || value.starts_with("workspace:") {
        return None;
    }
    let split = value.rfind('@')?;
    if split == 0 {
        return None;
    }
    Some((value[..split].to_string(), value[split + 1..].to_string()))
}

fn package_name_from_location(location: &str) -> Option<String> {
    let tail = location.rsplit("node_modules/").next()?;
    if tail.starts_with('@') {
        let mut parts = tail.split('/');
        Some(format!("{}/{}", parts.next()?, parts.next()?))
    } else {
        Some(tail.split('/').next()?.to_string())
    }
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

fn platform_matches(package: &LockedPackage) -> bool {
    list_matches(&package.os, node_os()) && list_matches(&package.cpu, node_arch())
}

fn node_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

fn list_matches(values: &[String], current: &str) -> bool {
    if values.iter().any(|value| value == &format!("!{current}")) {
        return false;
    }
    let positive = values
        .iter()
        .filter(|value| !value.starts_with('!'))
        .collect::<Vec<_>>();
    positive.is_empty() || positive.into_iter().any(|value| value.as_str() == current)
}

fn node_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        other => other,
    }
}

pub(crate) fn is_node_builtin(name: &str) -> bool {
    let name = name.strip_prefix("node:").unwrap_or(name);
    matches!(
        name,
        "assert"
            | "assert/strict"
            | "async_hooks"
            | "buffer"
            | "child_process"
            | "cluster"
            | "console"
            | "constants"
            | "crypto"
            | "dgram"
            | "diagnostics_channel"
            | "dns"
            | "dns/promises"
            | "domain"
            | "events"
            | "fs"
            | "fs/promises"
            | "http"
            | "http2"
            | "https"
            | "module"
            | "net"
            | "os"
            | "path"
            | "path/posix"
            | "path/win32"
            | "perf_hooks"
            | "process"
            | "punycode"
            | "querystring"
            | "readline"
            | "readline/promises"
            | "repl"
            | "stream"
            | "stream/consumers"
            | "stream/promises"
            | "stream/web"
            | "string_decoder"
            | "sys"
            | "timers"
            | "timers/promises"
            | "tls"
            | "trace_events"
            | "tty"
            | "url"
            | "util"
            | "util/types"
            | "v8"
            | "vm"
            | "wasi"
            | "worker_threads"
            | "zlib"
            | "node:test"
            | "test"
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs};

    use tempfile::tempdir;

    use super::{JavascriptClosureError, production_closure};

    #[test]
    fn walks_bun_production_closure_exactly() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("bun.lock"), r#"{
          // bun.lock is JSONC and permits trailing commas.
          "lockfileVersion": 1,
          "workspaces": {
            "": { "name": "root", "dependencies": { "runtime": "1.0.0", "@scope/pkg": "2.0.0", "member": "workspace:*" }, "optionalDependencies": { "optional": "3.0.0" }, "devDependencies": { "dev": "1.0.0", "shared": "2.0.0" } },
            "packages/member": { "name": "member", "dependencies": { "workspace-runtime": "4.0.0" } },
          },
          "packages": {
            "runtime": ["runtime@1.0.0", "", { "dependencies": { "transitive": "1.1.0", "shared": "1.0.0", "fs": "1.0.0" } }],
            "transitive": ["transitive@1.1.0", "", { "dependencies": { "runtime": "1.0.0" } }],
            "shared@1.0.0": ["shared@1.0.0", "", {}],
            "shared@2.0.0": ["shared@2.0.0", "", {}],
            "@scope/pkg": ["@scope/pkg@2.0.0", "", {}],
            "optional": ["optional@3.0.0", "", {}],
            "workspace-runtime": ["workspace-runtime@4.0.0", "", {}],
            "dev": ["dev@1.0.0", "", { "dependencies": { "shared": "2.0.0" } }],
          },
        }"#).unwrap();

        let closure = production_closure(temp.path()).unwrap();
        let expected = [
            ("runtime", "1.0.0"),
            ("transitive", "1.1.0"),
            ("shared", "1.0.0"),
            ("@scope/pkg", "2.0.0"),
            ("optional", "3.0.0"),
            ("workspace-runtime", "4.0.0"),
        ]
        .into_iter()
        .map(|(name, version)| (name.to_string(), version.to_string()))
        .collect::<BTreeSet<_>>();
        assert_eq!(closure, expected);
    }

    #[test]
    fn reports_missing_and_unsupported_lockfiles() {
        let temp = tempdir().unwrap();
        assert!(matches!(
            production_closure(temp.path()),
            Err(JavascriptClosureError::MissingLockfile { .. })
        ));
        fs::write(
            temp.path().join("package-lock.json"),
            r#"{"lockfileVersion":2,"packages":{"":{}}}"#,
        )
        .unwrap();
        assert!(matches!(
            production_closure(temp.path()),
            Err(JavascriptClosureError::UnsupportedLockfile { .. })
        ));
    }
}
