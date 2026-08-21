# The report shape

What every run produces, in what order, and what a later run may rely on. Written so a second version cannot quietly change the contract.

Each run writes two files into `--out`:

| file | audience |
|---|---|
| `harness-audit-report.md` | a person |
| `harness-audit-report.json` | a diff, a dashboard, a pipeline |

Same result, two renderings. The JSON is the record; the Markdown is a view of it.

---

## 1 · The severity vocabulary

Five values. They are not a scale of badness, they are five different statements.

| value | means | printed as |
|---|---|---|
| `blocker` | declared and not working, or a fence you appear to want is not in place | Broken |
| `gap` | a guardrail is absent | Missing |
| `unknown` | the check ran and could not reach its evidence | Could not see |
| `note` | a property worth knowing, not a defect | Worth knowing |
| `ok` | checked, and found in place | Clear |

**`unknown` is the load-bearing one.** No check may resolve an unreachable condition to `ok`. When a hook path is built from a variable, when there is no permission block to read, when nothing records capability usage, the answer is `unknown` and it is printed above the passes rather than folded into them.

The labels in the right-hand column live in `audit-copy.json` and can be renamed. The five values themselves are the contract and do not change.

---

## 2 · The Markdown report, in order

1. **Title and one-line statement of what the tool does.** Both from `audit-copy.json`.
2. **What was scanned.** Project directory, agent-config directory, timestamp, engine version, and whether paths were redacted.
3. **What this run says.** A five-row count table, then the reading rule that sends you to the unknowns first.
4. **The findings, grouped by severity**, in the order `blocker`, `gap`, `unknown`, `note`, `ok`. Within a group, findings appear in the order the engine produced them, which is discovery, instructions, settings, hooks, evidence, fences, unattended, inventory.
5. **Inventory.** Families detected, settings files read, hooks declared, evidence artifacts found, capability counts.
6. **What this audit cannot tell you.** The standing limits, printed in full on every run.
7. **Footer.** A statement that nothing left the machine.

### The shape of one finding

```
### H11 · A hook points at a file that is not there

**What it found.**  one sentence, from the copy file

```
checked: 2 · missing: 1        the machine-readable facts, verbatim
```

Evidence:

- `PostToolUse: .claude/hooks/post-tool.mjs`      up to 12 items, then a count

**What it costs.**  why it matters, from the copy file

**What closes it.**  what to do about it, from the copy file

**Where that lives.**  optional, printed only when a route is set
```

Four fixed slots: what it found, the facts, what it costs, what closes it. The facts block is the only part the engine authors. Everything else is text-layer.

---

## 3 · The JSON record

```json
{
  "tool": "Harness Audit",
  "engine_version": "1.0.0",
  "generated": "2026-08-15 21:33:19Z",
  "scanned": {
    "project": "<PROJECT>",
    "agent_config": "<HOME>",
    "redacted": true
  },
  "counts": { "blocker": 0, "gap": 2, "unknown": 0, "note": 6, "ok": 13 },
  "findings": [
    {
      "id": "H11",
      "group": "hooks",
      "severity": "blocker",
      "facts": { "checked": 2, "missing": 1 },
      "evidence": ["PostToolUse: .claude/hooks/post-tool.mjs"]
    }
  ],
  "inventory": {
    "profiles": [{ "id": "claude-code", "label": "Claude Code", "markers": [] }],
    "settings": [],
    "hooks": [{ "slot": "", "lifecycle": "", "from": "", "command": "" }],
    "capabilities": { "skills (home)": 48 },
    "evidence": [{ "path": "", "origin": "", "ageDays": 0, "bytes": 0 }]
  }
}
```

**Stable across versions:** the five severity values, the `id` of any check that still exists, `counts`, and the top-level key names.

**Not stable:** the contents of `facts`, which is per-check and may gain keys. Read it, do not depend on its shape.

**Redaction** replaces the project and agent-config prefixes with `<PROJECT>` and `<HOME>` in every string of both outputs, including inside `facts` and `inventory`. It substitutes prefixes only. Names below those roots survive, so a report from a repository whose folder names are themselves sensitive needs more than this flag.

---

## 4 · The check register

Twenty-three checks. The severities each one is able to emit are listed so that an absent finding can be told from an impossible one.

| id | group | can emit |
|---|---|---|
| H01 | discovery | ok · unknown |
| H02 | instructions | ok · gap |
| H50 | instructions | note |
| H51 | instructions | ok · gap · unknown |
| H52 | instructions | note |
| H03 | settings | ok · gap |
| H04 | settings | ok · blocker |
| H10 | hooks | ok · note · gap |
| H11 | hooks | ok · blocker · unknown |
| H12 | hooks | unknown |
| H13 | hooks | note |
| H20 | evidence | ok · gap · unknown |
| H21 | evidence | ok · gap |
| H30 | fences | ok · gap · unknown |
| H31 | fences | ok · blocker |
| H32 | fences | ok · blocker · note |
| H33 | fences | note |
| H34 | fences | note |
| H40 | unattended | ok · gap |
| H41 | unattended | ok · note |
| H42 | unattended | ok · gap |
| H60 | inventory | ok · note |
| H61 | inventory | ok · unknown |

Checks that only emit one value are one-directional by design. `H12` for instance exists only to say that something could not be verified; there is no passing form of it, because the passing form is `H11` reporting a resolved target.

A check that finds nothing to say emits no row at all. `H12` is absent when no hook path uses a variable, and that absence is not a pass.

---

## 5 · Reading two runs against each other

The JSON is written to be diffed. The useful comparison is not the counts, it is the set of `id` plus `severity` pairs:

```
node -e "const a=require('./before.json'),b=require('./after.json');const k=r=>new Set(r.findings.filter(f=>f.severity!=='ok').map(f=>f.id+':'+f.severity));const A=k(a),B=k(b);console.log('closed:',[...A].filter(x=>!B.has(x)));console.log('opened:',[...B].filter(x=>!A.has(x)))"
```

A finding moving from `gap` to `ok` is progress. A finding moving from `ok` to `unknown` is usually the more interesting event, because it means something that used to be verifiable no longer is.

---

## 6 · Exit codes

| code | meaning |
|---|---|
| 0 | the audit ran and wrote a report |
| 1 | the audit ran and the `--fail-on` level was met |
| 3 | the audit could not run, and said why on stderr |

`--fail-on` takes `none` (the default), `note`, `unknown`, `gap`, or `blocker`, and compares against the severity order `ok < note < unknown < gap < blocker`. Findings marked `ok` never trigger it.

Exit `3` is reserved for cannot-run. It is never used for findings, so a pipeline can tell a setup with problems apart from an audit that failed to happen.
