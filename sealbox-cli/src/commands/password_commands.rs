use anyhow::{Context, Result};
use rand::seq::{IndexedRandom, SliceRandom};
use serde_json::json;

use crate::{PasswordCommands, PasswordPolicyArgs, config::Config, output::OutputManager};

pub const DEFAULT_PASSWORD_LENGTH: usize = 24;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
const AMBIGUOUS: &str = "O0oIl1|";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl PasswordPolicyArgs {
    pub fn to_policy(&self) -> PasswordPolicy {
        PasswordPolicy {
            length: self.length.unwrap_or(DEFAULT_PASSWORD_LENGTH),
            lowercase: !self.no_lowercase,
            uppercase: !self.no_uppercase,
            numbers: !self.no_numbers,
            symbols: !(self.no_symbols || self.alphanumeric),
            exclude_ambiguous: self.exclude_ambiguous,
        }
    }

    pub fn has_explicit_generation_option(&self) -> bool {
        self.length.is_some()
            || self.alphanumeric
            || self.no_symbols
            || self.no_numbers
            || self.no_uppercase
            || self.no_lowercase
            || self.exclude_ambiguous
    }
}

pub async fn handle_command(command: PasswordCommands, config: &Config) -> Result<()> {
    let output = OutputManager::new(config.output.format.clone());

    match command {
        PasswordCommands::Generate { count, policy } => {
            generate_password_command(&output, count, policy).await
        }
    }
}

async fn generate_password_command(
    output: &OutputManager,
    count: usize,
    policy_args: PasswordPolicyArgs,
) -> Result<()> {
    if count == 0 {
        anyhow::bail!("Password count must be greater than zero");
    }

    let policy = policy_args.to_policy();
    let passwords = generate_passwords(&policy, count)?;
    output.print_passwords(&passwords)
}

pub fn generate_passwords(policy: &PasswordPolicy, count: usize) -> Result<Vec<String>> {
    if count == 0 {
        anyhow::bail!("Password count must be greater than zero");
    }

    (0..count).map(|_| generate_password(policy)).collect()
}

pub fn generate_password(policy: &PasswordPolicy) -> Result<String> {
    let classes = enabled_classes(policy)?;
    if policy.length < classes.len() {
        anyhow::bail!(
            "Password length must be at least {} to include each enabled character class",
            classes.len()
        );
    }

    let all_chars = classes.iter().flatten().copied().collect::<Vec<char>>();
    let mut rng = rand::rng();
    let mut password = Vec::with_capacity(policy.length);

    for class in &classes {
        password.push(
            *class
                .choose(&mut rng)
                .context("Enabled character class is empty")?,
        );
    }

    for _ in password.len()..policy.length {
        password.push(
            *all_chars
                .choose(&mut rng)
                .context("No password characters available")?,
        );
    }

    password.shuffle(&mut rng);
    Ok(password.into_iter().collect())
}

fn enabled_classes(policy: &PasswordPolicy) -> Result<Vec<Vec<char>>> {
    let mut classes = Vec::new();

    if policy.lowercase {
        classes.push(filtered_chars(LOWERCASE, policy.exclude_ambiguous));
    }
    if policy.uppercase {
        classes.push(filtered_chars(UPPERCASE, policy.exclude_ambiguous));
    }
    if policy.numbers {
        classes.push(filtered_chars(NUMBERS, policy.exclude_ambiguous));
    }
    if policy.symbols {
        classes.push(filtered_chars(SYMBOLS, policy.exclude_ambiguous));
    }

    if classes.is_empty() {
        anyhow::bail!("At least one character class must be enabled");
    }

    if classes.iter().any(Vec::is_empty) {
        anyhow::bail!("At least one enabled character class has no available characters");
    }

    Ok(classes)
}

fn filtered_chars(chars: &str, exclude_ambiguous: bool) -> Vec<char> {
    chars
        .chars()
        .filter(|candidate| !exclude_ambiguous || !AMBIGUOUS.contains(*candidate))
        .collect()
}

pub fn print_generated_password(output: &OutputManager, password: &str) -> Result<()> {
    output.print_value(&json!({ "generated_password": password }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> PasswordPolicy {
        PasswordPolicy {
            length: DEFAULT_PASSWORD_LENGTH,
            lowercase: true,
            uppercase: true,
            numbers: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }

    fn has_any(value: &str, chars: &str) -> bool {
        value.chars().any(|candidate| chars.contains(candidate))
    }

    #[test]
    fn test_generate_password_uses_default_length() {
        let password = generate_password(&default_policy()).unwrap();

        assert_eq!(password.len(), DEFAULT_PASSWORD_LENGTH);
    }

    #[test]
    fn test_generate_password_includes_each_enabled_class() {
        let password = generate_password(&default_policy()).unwrap();

        assert!(has_any(&password, LOWERCASE));
        assert!(has_any(&password, UPPERCASE));
        assert!(has_any(&password, NUMBERS));
        assert!(has_any(&password, SYMBOLS));
    }

    #[test]
    fn test_generate_password_supports_alphanumeric_policy() {
        let policy = PasswordPolicy {
            symbols: false,
            ..default_policy()
        };

        let password = generate_password(&policy).unwrap();

        assert!(
            password
                .chars()
                .all(|candidate| candidate.is_ascii_alphanumeric())
        );
        assert!(has_any(&password, LOWERCASE));
        assert!(has_any(&password, UPPERCASE));
        assert!(has_any(&password, NUMBERS));
    }

    #[test]
    fn test_generate_password_excludes_ambiguous_characters() {
        let policy = PasswordPolicy {
            length: 128,
            symbols: false,
            exclude_ambiguous: true,
            ..default_policy()
        };

        let password = generate_password(&policy).unwrap();

        assert!(
            !password
                .chars()
                .any(|candidate| AMBIGUOUS.contains(candidate))
        );
    }

    #[test]
    fn test_generate_password_rejects_no_enabled_classes() {
        let policy = PasswordPolicy {
            lowercase: false,
            uppercase: false,
            numbers: false,
            symbols: false,
            ..default_policy()
        };

        assert!(generate_password(&policy).is_err());
    }

    #[test]
    fn test_generate_password_rejects_length_too_short_for_classes() {
        let policy = PasswordPolicy {
            length: 3,
            ..default_policy()
        };

        assert!(generate_password(&policy).is_err());
    }

    #[test]
    fn test_generate_passwords_rejects_zero_count() {
        assert!(generate_passwords(&default_policy(), 0).is_err());
    }

    #[test]
    fn test_password_policy_args_alphanumeric_disables_symbols() {
        let args = PasswordPolicyArgs {
            length: Some(40),
            alphanumeric: true,
            no_symbols: false,
            no_numbers: false,
            no_uppercase: false,
            no_lowercase: false,
            exclude_ambiguous: true,
        };

        let policy = args.to_policy();

        assert_eq!(policy.length, 40);
        assert!(policy.lowercase);
        assert!(policy.uppercase);
        assert!(policy.numbers);
        assert!(!policy.symbols);
        assert!(policy.exclude_ambiguous);
    }
}
