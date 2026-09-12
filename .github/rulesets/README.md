# Rulesets

The branch and tag protection for this repository, as JSON rather than as
settings someone clicked once and cannot reproduce.

Apply or re-apply:

```bash
gh api --method POST repos/doug445/LinuxLocker/rulesets --input .github/rulesets/branch-main.json
gh api --method POST repos/doug445/LinuxLocker/rulesets --input .github/rulesets/tags-release.json
```

List what is live, and read one back:

```bash
gh api repos/doug445/LinuxLocker/rulesets --jq '.[] | "\(.id)  \(.name)  [\(.target)]  \(.enforcement)"'
gh api repos/doug445/LinuxLocker/rulesets/RULESET_ID --jq '.rules'
```

## What is enforced

**`branch-main.json`** — the default branch:

| Rule | Effect |
|---|---|
| `deletion` | `main` cannot be deleted |
| `non_fast_forward` | no force-pushing `main`; history cannot be rewritten |
| `required_status_checks` | a pull request merges into `main` only when every CI job in `lint.yml` has passed: `shellcheck`, `loopback` and `uki-fixtures` and `cmdline-fixtures` on both `ubuntu-latest` and `ubuntu-24.04-arm`. Not strict (the branch need not be up to date), and not enforced on branch creation |

The status-check rule exists for contributors: a filesystem handler or a
boot-stack patch that does not pass what CI runs must not merge. The contexts
are the job ids in `.github/workflows/lint.yml` (the jobs carry no `name:`,
so the id is the context, with the matrix runner in parentheses) — add or
rename a job there and change the list here in the same commit, or every pull
request waits for a check that never runs.

**`tags-release.json`** — every tag matching `v*`:

| Rule | Effect |
|---|---|
| `deletion` | a published version tag cannot be removed |
| `update` | a version tag cannot be moved to another commit |
| `non_fast_forward` | no force-pushing a tag over an existing one |

Creating *new* `v*` tags is unaffected — that is the `creation` rule, which is
deliberately not enabled.

## What is deliberately not enforced

This is a small repository with direct pushes to `main`. Rules that assume a
pull-request workflow would break it for no gain:

- **`pull_request`** — would forbid pushing to `main` at all. Contributors
  arrive by pull request anyway; the maintainer pushes directly.
- **`required_signatures`** — commits here are not GPG-signed, so this would
  reject every push, including your own.
- **`required_linear_history`** — would block merge commits. Dependabot's grouped
  pull request merges cleanly by squash, but this rule turns an ordinary "Merge"
  click into a confusing failure.

## Bypass, and getting unstuck

On `main`, `bypass_actors` names the repository admin role (`actor_id` 5)
with `bypass_mode: always`. That is what lets the maintainer push straight to
`main` past the status-check rule; GitHub reports it on every such push as
`Bypassed rule violations for refs/heads/main`. It also means `deletion` and
`non_fast_forward` do not bind the admin on `main`. The tag ruleset has no
bypass and binds everyone, the maintainer included — that is the guard that
catches a bad `--force` on a published version tag, from you or from tooling.

Nothing is locked: as an admin you can set a ruleset to `disabled`, do the
thing, and set it back.

Send the **whole** ruleset body, not just the changed field — `PUT` replaces the
ruleset, so a partial update silently drops the rules:

```bash
ID=$(gh api repos/doug445/LinuxLocker/rulesets --jq '.[] | select(.name=="release tags") | .id')

jq '.enforcement = "disabled"' .github/rulesets/tags-release.json > /tmp/off.json
gh api --method PUT "repos/doug445/LinuxLocker/rulesets/$ID" --input /tmp/off.json

# ... do the thing ...

gh api --method PUT "repos/doug445/LinuxLocker/rulesets/$ID" --input .github/rulesets/tags-release.json
```

Confirm the rules survived, every time:

```bash
gh api "repos/doug445/LinuxLocker/rulesets/$ID" --jq '.enforcement, (.rules|map(.type))'
```

## Status

**Applied to this repository on 2026-08-28** (both rulesets; `main` updated
2026-08-31 to add the status checks, and 2026-09-12 to add the
`cmdline-fixtures` jobs). Read back with the commands above: `main` enforces
`deletion`, `non_fast_forward` and `required_status_checks` with admin bypass;
`release tags` enforces `deletion`, `update` and `non_fast_forward` on `v*`
with no bypass. The behaviour was tested on 2026-08-23 on a sibling
repository: pushing a new `v*` tag succeeded, deleting it was rejected with
`GH013: Repository rule violations found`, and an ordinary fast-forward push to
`main` was unaffected. The disable/re-enable cycle above is how that test tag
was then removed.
