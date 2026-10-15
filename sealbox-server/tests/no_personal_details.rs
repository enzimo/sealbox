//! Tracked files carry no real contact details or personal host paths.
//!
//! This repository is public, release archives contain the README and LICENSE,
//! and Git history keeps old versions of every file. CONTRIBUTING.md
//! ("Personal details") lists what stays out and which made-up placeholders to
//! use. These checks catch what a machine can recognize without a list of real
//! values: email addresses outside reserved example domains, phone numbers
//! outside the fictional 555 ranges, and home folder paths with a real account
//! name. Names, handles and copied chats still need a reviewer.
//!
//! Sample values in this file are assembled at run time so the scan of this
//! file itself stays clean.

use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

const RULES: &str = "see CONTRIBUTING.md, Personal details";
const AT: &str = "@";

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b").unwrap()
});
// Domains reserved for examples (RFC 2606, RFC 6761) or private networks.
const EXAMPLE_DOMAINS: &[&str] = &["example.com", "example.net", "example.org"];
const EXAMPLE_TOP_LEVEL_DOMAINS: &[&str] = &[
    "example",
    "test",
    "invalid",
    "localhost",
    "internal",
    "local",
];
// GitHub's own shared addresses; personal noreply addresses name a login.
const SHARED_ADDRESSES: &[&str] = &["git@github.com", "noreply@github.com"];

static PHONE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\+[1-9][\d ().-]{8,18}\d").unwrap());
// North American numbers set aside for examples: area code 555, or the
// 555-0100 to 555-0199 lines in any area code.
static FICTIONAL_PHONE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:1555\d{7}|1\d{3}55501\d{2})$").unwrap());

static HOME_FOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:/home/|/Users/|[A-Za-z]:\\+Users\\+)([A-Za-z0-9._-]+)").unwrap()
});
// Generic accounts: placeholders, container users and shared folders.
const GENERIC_ACCOUNTS: &[&str] = &[
    "person",
    "user",
    "username",
    "you",
    "example",
    "exampleuser",
    "runner",
    "node",
    "ubuntu",
    "shared",
    "public",
];

/// The original Sealbox author's published address, kept as credit in
/// `sealbox-server/Cargo.toml`. It is the only real address allowed here.
fn upstream_author_credit() -> String {
    format!("morrisliu1994{AT}outlook.com")
}

/// Every match of `pattern` that the character before it does not rule out.
/// Stands in for a look-behind, which the regex crate does not support.
fn matches_not_after<'a>(
    pattern: &Regex,
    text: &'a str,
    ruled_out: impl Fn(char) -> bool,
) -> Vec<regex::Match<'a>> {
    let mut found = Vec::new();
    let mut start = 0;
    while let Some(m) = pattern.find_at(text, start) {
        let before = text[..m.start()].chars().next_back();
        if before.is_some_and(&ruled_out) {
            // Retry one character later, as a look-behind would.
            start = m.start() + text[m.start()..].chars().next().map_or(1, char::len_utf8);
        } else {
            found.push(m);
            start = m.end();
        }
    }
    found
}

fn is_example_email(address: &str) -> bool {
    let lower = address.to_lowercase();
    if SHARED_ADDRESSES.contains(&lower.as_str()) || lower == upstream_author_credit() {
        return true;
    }
    let domain = lower.rsplit_once('@').map_or("", |(_, domain)| domain);
    if EXAMPLE_DOMAINS
        .iter()
        .any(|example| domain == *example || domain.ends_with(&format!(".{example}")))
    {
        return true;
    }
    let top_level = domain.rsplit('.').next().unwrap_or("");
    EXAMPLE_TOP_LEVEL_DOMAINS.contains(&top_level)
}

fn is_real_phone(number: &str) -> bool {
    let digits: String = number.chars().filter(char::is_ascii_digit).collect();
    if !(10..=15).contains(&digits.len()) {
        return false; // Too short or long for a phone number: versions, offsets, counts.
    }
    !FICTIONAL_PHONE.is_match(&digits)
}

/// Each real-looking address, phone number or home path in `text`.
fn personal_details(text: &str) -> Vec<String> {
    // A local part right after ":" or "/" is a URL's user info
    // (https://user:secret@host), not an address.
    let emails = matches_not_after(&EMAIL, text, |c| {
        c.is_alphanumeric() || "_.%+:/-".contains(c)
    })
    .into_iter()
    .map(|m| m.as_str())
    .filter(|address| !is_example_email(address));
    let phones = matches_not_after(&PHONE, text, |c| c.is_alphanumeric() || "_.+/-".contains(c))
        .into_iter()
        .map(|m| m.as_str())
        .filter(|number| is_real_phone(number));
    let home_folders = HOME_FOLDER
        .captures_iter(text)
        .filter(|caps| !GENERIC_ACCOUNTS.contains(&caps[1].to_lowercase().as_str()))
        .map(|caps| caps.get(0).unwrap().as_str());
    emails
        .chain(phones)
        .chain(home_folders)
        .map(str::to_owned)
        .collect()
}

fn tracked_personal_details(project_root: &Path) -> Vec<String> {
    // Only tracked files ship; local configuration and databases are ignored.
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(project_root)
        .output()
        .expect("run git ls-files");
    assert!(output.status.success(), "git ls-files failed");
    let tracked = String::from_utf8(output.stdout).expect("UTF-8 file names");
    let mut findings = Vec::new();
    for relative_path in tracked.split('\0').filter(|path| !path.is_empty()) {
        let Ok(content) = std::fs::read(project_root.join(relative_path)) else {
            continue; // Deleted in the working tree but not yet committed.
        };
        if content.contains(&0) {
            continue; // Binary file.
        }
        let text = String::from_utf8_lossy(&content);
        for (index, line) in text.lines().enumerate() {
            findings.extend(
                personal_details(line)
                    .into_iter()
                    .map(|detail| format!("{relative_path}:{}: {detail}", index + 1)),
            );
        }
    }
    findings
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn tracked_files_have_no_personal_details() {
    let root = workspace_root();
    if !root.join(".git").exists() {
        eprintln!("skipped: not a Git checkout, so there is no list of tracked files");
        return;
    }
    assert_eq!(
        tracked_personal_details(&root),
        Vec::<String>::new(),
        "{RULES}"
    );
}

#[test]
fn real_looking_details_are_found() {
    let samples = [
        format!("write to pat{AT}mailbox.co"),
        format!("Pat <pat.lee+ci{AT}corp.example.co.uk>"),
        format!("1234+pat{AT}users.noreply.github.com"),
        format!("call +49 30 {}", "1234 5678"),
        format!("text +1 (312) {}", "867-5309"),
        format!("cd /home/{}", "pat/projects"),
        format!("open /Users/{}", "pat.lee/Desktop"),
        format!(r"C:\\Users\\{}", r"pat\repo"),
    ];
    for text in samples {
        assert_ne!(personal_details(&text), Vec::<String>::new(), "{text}");
    }
}

#[test]
fn placeholders_and_non_contact_text_pass() {
    let samples = [
        format!("alice{AT}example.com, bob{AT}mail.example.net, ops{AT}acme.example"),
        format!("person{AT}team.test and nobody{AT}example.invalid"),
        format!("git clone git{AT}github.com:example-owner/repo.git"),
        format!("https://user:secret{AT}api.vendor.com/v1"),
        format!("https://token{AT}github.com/example/skills"),
        format!("postgresql://synthetic{AT}raw.example:5432/db"),
        format!("authors = [\"luckywood <{}>\"]", upstream_author_credit()),
        "+15551234567, +1 555 000 0001, +1 415-555-0132".to_owned(),
        "version +1.2.3, offset +05:00, count +12345, date 2026-10-14T12:00:00+00:00".to_owned(),
        "/home/node/app, /home/runner/work, /Users/Shared, /home/<user>/repo".to_owned(),
        format!("{AT}decorator and npm {AT}scope/package{AT}1.2.3"),
    ];
    for text in samples {
        assert_eq!(personal_details(&text), Vec::<String>::new(), "{text}");
    }
}

#[test]
fn scan_reads_only_tracked_files() {
    let dir = tempfile::tempdir().unwrap();
    let real_address = format!("pat{AT}mailbox.co");
    std::fs::write(
        dir.path().join("tracked.md"),
        format!("contact {real_address}\n"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("local.env"),
        format!("OWNER={real_address}\n"),
    )
    .unwrap();
    std::fs::write(dir.path().join("image.bin"), format!("\0{real_address}")).unwrap();
    let git = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap()
            .status;
        assert!(status.success(), "git {args:?}");
    };
    git(&["init", "--quiet"]);
    git(&["add", "tracked.md", "image.bin"]);

    assert_eq!(
        tracked_personal_details(dir.path()),
        vec![format!("tracked.md:1: {real_address}")]
    );
}
