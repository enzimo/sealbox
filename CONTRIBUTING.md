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
- Commit with your GitHub noreply address
  (`git config user.email <id>+<login>@users.noreply.github.com`) and turn on
  GitHub's "Keep my email addresses private" and "Block command line pushes
  that expose my email" settings.
- Organization and repository names used in real addresses, and the original
  author's credit in `sealbox-server/Cargo.toml` and `LICENSE`, may stay.

`sealbox-server/tests/no_personal_details.rs` fails when a tracked file
contains an email address outside the reserved example domains, a phone number
outside the fictional 555 ranges, or a home folder path with a real account
name. It cannot recognize names, handles or copied chats without listing them,
so those still depend on review.
