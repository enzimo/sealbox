use std::io::{self, IsTerminal, Read};

use anyhow::{Context, Result};

use crate::output::OutputManager;

pub fn read_secret_from_tty_or_stdin(
    output: &OutputManager,
    tty_prompt: &str,
    value_name: &str,
) -> Result<String> {
    if io::stdin().is_terminal() {
        output.print_info(tty_prompt);
        return rpassword::read_password().with_context(|| format!("Failed to read {value_name}"));
    }

    let mut stdin = io::stdin();
    read_piped_secret(&mut stdin).with_context(|| format!("Failed to read {value_name} from stdin"))
}

fn read_piped_secret(reader: &mut impl Read) -> Result<String> {
    let mut value = String::new();
    reader.read_to_string(&mut value)?;
    Ok(trim_piped_secret(value))
}

fn trim_piped_secret(value: String) -> String {
    value.trim_end_matches(['\r', '\n']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_piped_secret_trims_trailing_newline() {
        let mut input = Cursor::new("secret-password\n");

        let value = read_piped_secret(&mut input).unwrap();

        assert_eq!(value, "secret-password");
    }

    #[test]
    fn test_read_piped_secret_preserves_internal_newline() {
        let mut input = Cursor::new("line-one\nline-two\n");

        let value = read_piped_secret(&mut input).unwrap();

        assert_eq!(value, "line-one\nline-two");
    }

    #[test]
    fn test_read_piped_secret_trims_crlf() {
        let mut input = Cursor::new("secret-password\r\n");

        let value = read_piped_secret(&mut input).unwrap();

        assert_eq!(value, "secret-password");
    }
}
