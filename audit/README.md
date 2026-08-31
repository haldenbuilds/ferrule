# Harness Audit

A read-only look at your coding-agent setup. It runs on your machine, against your own configuration, and reports three things: what you have, what you do not have, and what it could not see.

It measures. It does not claim.

---

## Why the third column exists

Most setup checks return green or they return red. This one returns green, red, and **could not see**, and it prints that third category first.

The reason is the single failure this whole tool is aimed at. A hook that is written into your settings file, whose script exists on disk, and that has never once left a trace is **indistinguishable from a hook that never runs**. You cannot tell those two apart by reading the configuration, and reading the configuration is what everybody does, including every tool that tells you your setup looks fine.

So this one separates *checked and clear* from *could not check*, and refuses to add the second to the first.

---

## Requirements

Node 18 or newer. Nothing else. No packages, no install, no build step.

```
node --version
```

If that prints v18 or higher, you are ready.

---

## Run it

From your project directory:

```
node harness-audit.mjs
```

Before it reads configuration, the command checks all six files named by `MANIFEST.json`
against their byte lengths and SHA-256 digests. A malformed manifest, missing file, or
changed file refuses with exit 3.

That writes two files into the current directory:

| file | what it is |
|---|---|
| `harness-audit-report.md` | the report you read |
| `harness-audit-report.json` | the same result as data, for diffing between runs |

Common variations:

```
node harness-audit.mjs --project /path/to/repo --out ./audit-out
node harness-audit.mjs --home ~/.claude            point at your agent config directory
node harness-audit.mjs --redact                    replace your paths with placeholders
node harness-audit.mjs --stale-days 30             widen the freshness window
node harness-audit.mjs --fail-on gap               exit 1 if anything at that level is found
node harness-audit.mjs --help
```

On Windows PowerShell the same commands work unchanged.

**Exit codes.** `0` it ran. `1` it ran and your `--fail-on` level was met. `3` it could not run and said why.

---

## What it does, and what it will not do

| | |
|---|---|
| **Reads** | your configuration files, your instruction files, and file names and timestamps under your project |
| **Runs** | the audit path launches nothing. `--self-test` launches this production CLI against local synthetic fixtures. There is no shell or eval |
| **Sends** | nothing. There is no network call in the engine. Search it for `fetch` and `http` and you will find neither |
| **Writes** | only inside `--out`. Nothing else on disk is touched |
| **Opens** | never a file it flags as credential-shaped. It matches on the name and stops there |

Those five lines are the posture. They are stated so you can check them rather than trust them, and the engine is one readable file so checking them is quick.

---

## What it checks

**Discovery.** Which agent setups are present, and whether an always-loaded instruction file and a settings file exist and parse. A settings file that does not parse is reported as broken rather than absent, because that is the quietest way for a whole configuration to become inert.

**Authored against installed.** Every hook declared in your settings is matched to the script it calls. A declaration pointing at a file that is not there is the gap between a guardrail you wrote and a guardrail you have. Where a path is built from a variable, the result is reported as could-not-see, never as a pass.

**Evidence.** Whether anything your wiring declares has actually left an artifact, and whether the newest one is recent. This is the check the tool exists for.

**Fences.** Whether your permission model denies anything, whether any rule grants everything, whether anything is set to ask first, and whether credential-shaped files sit in a version-controlled tree without an ignore rule covering them.

**Unattended readiness.** Whether anything runs at session end, whether there is a place completion markers land, and whether any run log exists at all.

**Instruction hygiene.** The size of what gets loaded on every turn, whether more than one instruction file competes without stated precedence, and whether the paths named inside them still exist.

**Inventory.** How many agents, skills, commands and hook scripts you have, and whether anything records which of them actually fire.

---

## How to read the report

Top to bottom, and the order is deliberate.

1. **Could not see.** Every check that could not reach its evidence. Read this first, because each line is a question about your setup that is currently open.
2. **Broken.** Where the configuration and the intent disagree.
3. **Missing.** Absent guardrails. Some of these you will not want, and deciding that is a legitimate outcome.
4. **Worth knowing.** Properties, not defects.
5. **Clear.** Checked and in place.

A finding is not an instruction. Several of them describe things a small project should not bother with. The value is that the decision becomes yours instead of accidental.

---

## Prove the tool before you trust it

```
node harness-audit.mjs --self-test
```

This builds two harnesses in a temporary directory: one with defects planted on purpose, one with the same shape and none of them. It then asserts that the engine reports **exactly** the planted list against the first and **none** of that list against the second.

The self-test launches the real buyer entrypoint for both halves. It also checks Markdown
and JSON report writes, path redaction, threshold exits in both directions, malformed
manifest refusal, missing-file refusal, and strict rejection of bare or unknown arguments.

Both halves matter. A checker that always fires is as useless as one that never does, and only running the broken half would hide that.

To read the fixtures yourself:

```
node harness-audit.mjs --emit-fixture ./fixture
```

That writes both harnesses to disk along with `EXPECTED.json`, the exact list the engine is graded against.

---

## Make it yours

Three files, and only one of them is code.

| file | holds |
|---|---|
| `harness-audit.mjs` | the mechanism. No buyer-facing prose, no wordmark |
| `audit-copy.json` | **every sentence the report prints.** Rename the tool, restate any finding, translate the whole thing |
| `harness-profiles.json` | where to look. Add a setup by adding an entry; the engine does not change |

**To brand it:** set `brand.name` and `brand.line` in `audit-copy.json`. Nothing is compiled in.

**To point readers somewhere:** the `routes` block at the bottom of `audit-copy.json` maps a finding id and the severity it reported, written `<id>.<severity>`, to a place you would send someone who wants to close it. Fifteen of the twenty-three ids carry one and eight are left empty, and the block names which eight and why. The key is read for exactly the row being printed, so a check that can report more than one thing routes per reading, and the severity you did not write a route for prints none. An empty route prints nothing, and a route that does not help is worse than no route. A route never prints against a finding that came back clear. Replace ours with your own, or empty the block.

**To support another setup:** copy a profile entry in `harness-profiles.json` and change the paths. `configDir` lets the same entry work whether the reader points at their project or at their config directory.

---

## What it cannot tell you

Stated here as well as in every report, because a limit that only appears in the output is a limit people read once.

- It reads configuration and files. It does not watch a live session, so it cannot prove a hook fired today. It can prove that one left a trace, and that a declared one points at a file that is not there.
- It checks one target per command, the script the interpreter is told to run. Arguments passed to that script are not followed.
- The ignore-file check reads the ignore file in every directory between the file and your project root, and does not evaluate negation rules or the full pathspec grammar.
- It matches credential-shaped **names**, never contents. A harmless file with a risky name gets flagged; a risky file with a harmless name does not.
- Counts of capabilities are counts of files and folders. It does not judge whether any of them are good.
- It looks four directories deep from your project root and skips build and dependency folders.
- A setup it has no profile for is reported as not detected, never as clean.

---

## Version and compatibility

**Version 1.0.3.**

Fixed in 1.0.3, and worth stating plainly because it concerns your privacy: on Windows, `--redact` cleaned the Markdown report but not the JSON record, which could still contain your home directory. The Markdown was always clean, and macOS and Linux were never affected. If you ran 1.0.2 or earlier on Windows with `--redact` and shared `harness-audit-report.json` with anyone, open it and check before assuming it was scrubbed. The self-test now walks the JSON record string by string, and runs an unredacted control first so the check cannot pass by finding nothing.

This release runs on Node 18 or newer and reads the setups listed in `harness-profiles.json`. That is the stated compatibility range and it is what this version is.

No update stream comes with it and none is implied. A later release is a separate thing, and if the setups it reads change shape, `harness-profiles.json` is the file that moves, which is why it is data rather than code.
