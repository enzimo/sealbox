# Contributing to Sealbox

See the README's "Contributing" section for the development workflow. This
file holds the rules that apply to everything committed here.

## Personal details

This repository is public. Release archives include the README, and Git
history keeps old versions of every file. Removing a personal detail later
means rewriting history. Keep these out of code, tests, documentation,
examples, plans and commit metadata:

- Real names, nicknames, handles, email addresses, phone numbers and chat or
  account IDs of maintainers, users or their assistants. This includes the
  names people give their own assistant or bot, team, instance or company.
- Real domain names, server addresses, machine names, runner names, host
  accounts, hardware details and host folder paths from anyone's own setup.
- Real IDs from a running deployment (tenant, token or secret IDs) and copied
  chat messages, emails, reports or logs from a person's real work.

What to do instead:

- Use made-up placeholders: `exampleuser`, `example-owner`, `alice`, `bob`,
  `jordan`, the assistant name `Nova`, the company `Acme`; domains under
  `example.com`, `example.net` or `.test`; phone numbers in the `+1555` range.
- Turn a real incident into a summary or a made-up equivalent before adding it
  to a test or note. Keep the behavior being tested, not the person's content.
- Describe your own machines generically and keep their exact names, accounts
  and paths in notes outside this repository.
- Commit with an anonymized email: your GitHub noreply address
  (`<id>+<login>@users.noreply.github.com`, shown at
  https://github.com/settings/emails). Any contributor may commit; the checks
  look only at the email, not the name. Use your login rather than your real
  name as `git config user.name`. Turn on GitHub's "Keep my email addresses
  private" and "Block command line pushes that expose my email" settings, so
  merges you make on github.com use the noreply address too.
- Organization and repository names used in real addresses, and the original
  author's credit in `sealbox-server/Cargo.toml` and `LICENSE`, may stay.

### Automated checks

`scripts/check_personal_details.py` reports email addresses outside the
reserved example domains, phone numbers outside the fictional 555 ranges, home
folder paths with a real account name, and commit emails that are not
anonymized (GitHub noreply addresses and service mailboxes such as
`noreply@github.com` pass; names are not checked). It checks tracked files and
commits: the email, the message and every added line, including lines a later
commit deleted. It needs only Python 3.9+ and Git. It cannot recognize names,
handles, machine names or copied chats without listing them, so those still
depend on review.

- Turn on the Git hooks once in every clone:
  `git config core.hooksPath .githooks`. They check staged files and the
  commit email (pre-commit), the commit message (commit-msg), and every
  commit a push would upload (pre-push).
- The **Personal details** workflow runs the checker's tests, then checks
  tracked files and only the commits each push or pull request adds
  (`--github-event`). A manual run checks every commit, and so does a run
  whose starting commit is missing, such as after a force push, with a
  warning. Its log shows where a finding is but not the value.
- `.personal-details-allowlist` records this project's decisions: `text:`
  lines for real values that may appear and `account:` lines for made-up
  account names in example paths. It does not list who may commit.
  Fix a finding instead of adding it there.
- A detail that was already pushed stays in history after a new commit deletes
  it. Follow `docs/personal-details-cleanup.md`.
