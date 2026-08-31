#!/usr/bin/env node
/*
 * harness-audit.mjs
 * -------------------------------------------------------------------------------------------
 * A READ-ONLY self-audit for a coding-agent harness.
 *
 * It runs on your own machine, against your own setup, and reports three things:
 *   what you have  |  what you do not have  |  what it could not see
 *
 * The third column is the point. A check that cannot reach its evidence reports UNKNOWN and is
 * never counted as a pass. A tool that only ever returns green is decoration.
 *
 * POSTURE, stated so you can verify it rather than trust it:
 *   - the audit path reads files and runs nothing. No shell, no eval, no network.
 *   - --self-test launches this production CLI against local synthetic fixtures only.
 *   - no network. This file contains no fetch, no http, no socket.
 *   - writes only inside --out (default: the current directory). Nothing else on disk is touched.
 *   - never prints the contents of a file it flags as secret-shaped. Paths only.
 *
 * MECHANISM IS HERE. WORDS ARE NOT.
 *   Every buyer-facing sentence lives in audit-copy.json. Every "where do I look" rule lives in
 *   harness-profiles.json. Swap either without touching this file. That is also how you brand it:
 *   set brand.name and brand.line in the copy file. No wordmark is compiled in.
 *
 * REQUIREMENTS: Node 18 or newer. No packages, no install step.
 *
 * USAGE
 *   node harness-audit.mjs                              audit the current directory
 *   node harness-audit.mjs --project . --out ./audit-out
 *   node harness-audit.mjs --redact                     replace your paths with placeholders
 *   node harness-audit.mjs --self-test                  positive control, both halves
 *   node harness-audit.mjs --emit-fixture ./fixture     write the self-test fixture to disk
 *   node harness-audit.mjs --fail-on gap                exit 1 when something at or above that level is found
 *
 * EXIT CODES
 *   0  the audit ran and produced a report
 *   1  the audit ran and --fail-on was met
 *   3  the audit could not run (bad arguments, unreadable target, self-test failure)
 * -------------------------------------------------------------------------------------------
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ENTRYPOINT = fileURLToPath(import.meta.url);
const TOOL_VERSION = '1.0.1';
const DELIVERY_FILE_COUNT = 6;

const SEVERITY_ORDER = ['ok', 'note', 'unknown', 'gap', 'blocker'];
const rank = (s) => SEVERITY_ORDER.indexOf(s);

/* ------------------------------------------------------------------ small file helpers */

function readTextSafe(p) {
  try {
    let t = fs.readFileSync(p, 'utf8');
    if (t.charCodeAt(0) === 0xfeff) t = t.slice(1);
    return t;
  } catch {
    return null;
  }
}

function readJsonSafe(p) {
  const raw = readTextSafe(p);
  if (raw === null) return { ok: false, reason: 'unreadable', value: null };
  try {
    return { ok: true, reason: '', value: JSON.parse(raw) };
  } catch (e) {
    return { ok: false, reason: String(e.message || e), value: null };
  }
}

function deliveryFailure(message) {
  console.error(`[harness-audit] CANNOT RUN: delivery verification failed: ${message}`);
  return 3;
}

// Verify the package before reading audit-copy.json, harness-profiles.json, or the fixture.
// MANIFEST.json cannot list itself, so it names the other six shipped files exactly.
function verifyDelivery() {
  const manifestPath = path.join(HERE, 'MANIFEST.json');
  const manifestRes = readJsonSafe(manifestPath);
  if (!manifestRes.ok) return { ok: false, reason: `MANIFEST.json ${manifestRes.reason}` };
  const manifest = manifestRes.value;
  if (!Number.isInteger(manifest?.file_count) || manifest.file_count !== DELIVERY_FILE_COUNT) {
    return { ok: false, reason: `MANIFEST.json file_count must be ${DELIVERY_FILE_COUNT}` };
  }
  if (!Array.isArray(manifest.files) || manifest.files.length !== manifest.file_count) {
    return { ok: false, reason: `MANIFEST.json must list exactly ${manifest.file_count} files` };
  }

  const seen = new Set();
  for (const entry of manifest.files) {
    if (!entry || typeof entry.path !== 'string' || !entry.path.trim()) {
      return { ok: false, reason: 'MANIFEST.json contains an entry without a path' };
    }
    const rel = entry.path.replaceAll('\\', '/');
    if (rel === 'MANIFEST.json' || path.isAbsolute(rel) || rel.split('/').includes('..')) {
      return { ok: false, reason: `MANIFEST.json contains an unsafe path: ${entry.path}` };
    }
    if (seen.has(rel)) return { ok: false, reason: `MANIFEST.json lists ${rel} more than once` };
    seen.add(rel);
    if (!Number.isInteger(entry.bytes) || entry.bytes < 0) {
      return { ok: false, reason: `MANIFEST.json has no usable byte length for ${rel}` };
    }
    if (typeof entry.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(entry.sha256)) {
      return { ok: false, reason: `MANIFEST.json has no usable sha256 for ${rel}` };
    }

    const abs = path.resolve(HERE, rel);
    if (path.dirname(abs) !== HERE) return { ok: false, reason: `MANIFEST.json path leaves the package: ${rel}` };
    let body;
    let stat;
    try {
      body = fs.readFileSync(abs);
      stat = fs.statSync(abs);
    } catch (e) {
      return { ok: false, reason: `listed file is missing or unreadable: ${rel} (${e.message})` };
    }
    if (!stat.isFile()) return { ok: false, reason: `listed path is not a file: ${rel}` };
    if (stat.size !== entry.bytes) {
      return { ok: false, reason: `byte length mismatch for ${rel}: expected ${entry.bytes}, found ${stat.size}` };
    }
    const digest = createHash('sha256').update(body).digest('hex');
    if (digest !== entry.sha256.toLowerCase()) {
      return { ok: false, reason: `sha256 mismatch for ${rel}` };
    }
  }
  return { ok: true, checked: seen.size };
}

function statSafe(p) {
  try {
    return fs.statSync(p);
  } catch {
    return null;
  }
}

function isDir(p) {
  const s = statSafe(p);
  return !!s && s.isDirectory();
}

function isFile(p) {
  const s = statSafe(p);
  return !!s && s.isFile();
}

function listDirSafe(p) {
  try {
    return fs.readdirSync(p, { withFileTypes: true });
  } catch {
    return [];
  }
}

// Bounded, symlink-refusing walk. A self-audit that hangs on a recursive link is a self-audit
// nobody runs twice.
function walk(root, { maxDepth = 4, skipDirs = [], maxEntries = 20000 } = {}) {
  const out = [];
  if (!isDir(root)) return out;
  const skip = new Set(skipDirs);
  const queue = [{ dir: root, depth: 0 }];
  while (queue.length && out.length < maxEntries) {
    const { dir, depth } = queue.shift();
    for (const ent of listDirSafe(dir)) {
      if (ent.isSymbolicLink()) continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (skip.has(ent.name)) continue;
        if (depth < maxDepth) queue.push({ dir: full, depth: depth + 1 });
      } else if (ent.isFile()) {
        out.push(full);
        if (out.length >= maxEntries) break;
      }
    }
  }
  return out;
}

const daysSince = (mtimeMs, nowMs) => Math.floor((nowMs - mtimeMs) / 86400000);

/* ------------------------------------------------------------------ path-shaped token parsing */

const SCRIPT_EXT = ['.ps1', '.sh', '.bash', '.js', '.mjs', '.cjs', '.py', '.rb', '.bat', '.cmd', '.ts', '.exe'];
const ARTIFACT_EXT = ['.log', '.jsonl', '.json', '.txt', '.tsv', '.csv', '.md', '.flag'];

const VAR_PATTERNS = [/\$\{[A-Za-z_][A-Za-z0-9_]*\}/, /\$[A-Za-z_][A-Za-z0-9_]*/, /%[A-Za-z_][A-Za-z0-9_]*%/, /\$env:/i];

const hasUnexpandedVar = (s) => VAR_PATTERNS.some((re) => re.test(s));

// Pull quoted runs and whitespace-separated words out of a command line, then keep the ones that
// look like a path carrying one of the extensions we care about.
function tokenize(cmd) {
  const tokens = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(cmd)) !== null) tokens.push(m[1] ?? m[2] ?? m[3]);
  return tokens;
}

function pathLikeTokens(cmd, exts) {
  const hits = [];
  for (const raw of tokenize(cmd)) {
    const t = raw.replace(/^[('"`]+/, '').replace(/[)'"`,;]+$/, '');
    if (!t) continue;
    const lower = t.toLowerCase();
    if (!exts.some((e) => lower.endsWith(e))) continue;
    hits.push(t);
  }
  return hits;
}

// ONE TARGET PER COMMAND SEGMENT, and it is the script the interpreter is told to run. Anything
// after that is an argument to that script, and a launcher taking the name of a second script as an
// argument is a common and sensible pattern. Treating every script-shaped token as a target
// reported seven working hooks as broken on the first real setup this was pointed at, which is the
// precise failure mode that makes a diagnostic worth ignoring.
const FILE_FLAGS = new Set(['-file', '--file', '-f', '-script', '--script']);

function hookTargets(cmd) {
  const targets = [];
  for (const segment of cmd.split(/&&|\|\||;|(?<!\|)\|(?!\|)/)) {
    const tokens = tokenize(segment).map((t) => t.replace(/^[('"`]+/, '').replace(/[)'"`,]+$/, ''));
    const isScript = (t) => SCRIPT_EXT.some((e) => t.toLowerCase().endsWith(e));
    let target = null;
    for (let i = 0; i < tokens.length - 1; i++) {
      if (FILE_FLAGS.has(tokens[i].toLowerCase()) && tokens[i + 1]) {
        target = tokens[i + 1];
        break;
      }
    }
    if (!target) target = tokens.find((t) => isScript(t) && !t.startsWith('-')) || null;
    if (target && isScript(target)) targets.push(target);
  }
  return targets;
}

function resolveCandidate(token, roots) {
  const cleaned = token.replace(/^\.[\\/]/, '');
  if (path.isAbsolute(token) && isFile(token)) return token;
  for (const r of roots) {
    const p = path.resolve(r, cleaned);
    if (isFile(p)) return p;
  }
  return null;
}

/* ------------------------------------------------------------------ gitignore, deliberately naive */

// A simple line matcher. It does NOT evaluate negation or the full pathspec grammar, and the report
// says so. It DOES walk up the directory chain and read the ignore file in each ancestor, because
// leaving that out produced a confident wrong answer on the first real setup it was pointed at:
// three files were called exposed while a nested ignore file was covering all three.
function matchesIgnoreLine(rawLine, relToDir) {
  const line = rawLine.trim();
  if (!line || line.startsWith('#') || line.startsWith('!')) return null;
  const pat = line.replace(/^\//, '').replace(/^\*\*\//, '').replace(/\/$/, '');
  if (!pat) return null;
  const base = relToDir.split('/').pop();
  if (pat === '*' || pat === '**') return line;
  if (pat === relToDir || pat === base) return line;
  if (pat.includes('*')) {
    const rx = new RegExp(
      '^' + pat.split('*').map((s) => s.replace(/[.+^${}()|[\]\\]/g, '\\$&')).join('[^/]*') + '$'
    );
    if (rx.test(base) || rx.test(relToDir)) return line;
  }
  if (relToDir.startsWith(pat + '/')) return line;
  return null;
}

function gitignoreCovers(projectDir, absPath, cache) {
  let dir = path.dirname(absPath);
  const stop = path.resolve(projectDir);
  for (let guard = 0; guard < 64; guard++) {
    const ignorePath = path.join(dir, '.gitignore');
    if (!cache.has(ignorePath)) {
      const t = readTextSafe(ignorePath);
      cache.set(ignorePath, t === null ? null : t.split(/\r?\n/));
    }
    const lines = cache.get(ignorePath);
    if (lines) {
      const rel = path.relative(dir, absPath).split(path.sep).join('/');
      for (const l of lines) {
        const hit = matchesIgnoreLine(l, rel);
        if (hit) return `${path.relative(stop, ignorePath).split(path.sep).join('/') || '.gitignore'}: ${hit}`;
      }
    }
    if (path.resolve(dir) === stop) break;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/* ------------------------------------------------------------------ findings */

class Findings {
  constructor() {
    this.rows = [];
  }
  add(id, group, severity, facts, evidence = []) {
    this.rows.push({ id, group, severity, facts, evidence });
  }
  has(id) {
    return this.rows.some((r) => r.id === id);
  }
  ids() {
    return this.rows.map((r) => r.id);
  }
  counts() {
    const c = { blocker: 0, gap: 0, unknown: 0, note: 0, ok: 0 };
    for (const r of this.rows) c[r.severity] = (c[r.severity] || 0) + 1;
    return c;
  }
}

/* ------------------------------------------------------------------ the audit itself */

// The project directory and the agent-config directory are usually different, and are allowed to be
// the same. Deduplicate once, here, or every count below is doubled when they coincide.
const dedupeRoots = (projectDir, homeDir) =>
  [path.resolve(projectDir), path.resolve(homeDir)].filter((v, i, a) => a.indexOf(v) === i);

// A profile path like ".claude/settings.json" is written from the project root. But the natural
// thing to pass as the agent-config directory IS the .claude directory, and against that root the
// same path resolves one level too deep and the whole config reads as absent. So every profile path
// is tried both ways whenever the root looks like the config directory itself. Under-reading a real
// setup is the failure this tool exists to catch, and it should not commit it first.
function profilePaths(roots, rel, profile) {
  const out = [];
  const cd = profile.configDir;
  const norm = rel.split('\\').join('/');
  for (const root of roots) {
    out.push({ root, abs: path.resolve(root, rel) });
    if (!cd) continue;
    if (norm !== cd && !norm.startsWith(cd + '/')) continue;
    const base = path.basename(root);
    if (base !== cd && !base.startsWith(cd + '-') && !base.startsWith(cd + '.')) continue;
    const stripped = norm === cd ? '.' : norm.slice(cd.length + 1);
    out.push({ root, abs: path.resolve(root, stripped) });
  }
  return out;
}

function detectProfiles(profiles, roots) {
  const detected = [];
  for (const p of profiles) {
    const marks = [];
    for (const rel of p.markers) {
      const hit = profilePaths(roots, rel, p).find((c) => isFile(c.abs) || isDir(c.abs));
      if (hit) marks.push(hit.abs);
    }
    if (marks.length) detected.push({ profile: p, markers: marks });
  }
  return detected;
}

function collectHooks(hooksObj, profile) {
  // Walk the hooks tree and collect every {type:'command', command:'...'} leaf, remembering which
  // top-level slot it hung from. Shape-tolerant on purpose: harness vendors move this around.
  const found = [];
  if (!hooksObj || typeof hooksObj !== 'object') return found;
  for (const [slot, val] of Object.entries(hooksObj)) {
    const stack = [val];
    while (stack.length) {
      const node = stack.pop();
      if (Array.isArray(node)) {
        stack.push(...node);
      } else if (node && typeof node === 'object') {
        if (typeof node.command === 'string' && node.command.trim()) {
          found.push({ slot, command: node.command.trim(), timeout: node.timeout ?? null });
        }
        for (const v of Object.values(node)) if (v && typeof v === 'object') stack.push(v);
      }
    }
  }
  const lifecycle = profile.lifecycle || {};
  for (const h of found) {
    h.lifecycle = Object.keys(lifecycle).find((k) => (lifecycle[k] || []).includes(h.slot)) || 'other';
  }
  return found;
}

function runAudit(opts) {
  const { projectDir, homeDir, staleDays, profiles, nowMs } = opts;
  const F = new Findings();
  const inventory = { profiles: [], settings: [], hooks: [], capabilities: {}, evidence: [] };
  const scanRoots = dedupeRoots(projectDir, homeDir);
  const scopeOf = (root) => (path.resolve(root) === path.resolve(projectDir) ? 'project' : 'home');

  /* --- discovery ------------------------------------------------------------------------ */

  const detected = detectProfiles(profiles, scanRoots);
  if (!detected.length) {
    F.add('H01', 'discovery', 'unknown', { checked: profiles.map((p) => p.id) });
    return { findings: F, inventory };
  }
  F.add('H01', 'discovery', 'ok', { families: detected.map((d) => d.profile.id) });
  inventory.profiles = detected.map((d) => ({ id: d.profile.id, label: d.profile.label, markers: d.markers }));

  /* --- instruction files ---------------------------------------------------------------- */

  const instructionFiles = [];
  for (const d of detected) {
    for (const rel of d.profile.instructionFiles || []) {
      for (const { root, abs } of profilePaths(scanRoots, rel, d.profile)) {
        if (isFile(abs) && !instructionFiles.some((i) => i.path === abs)) {
          instructionFiles.push({ path: abs, bytes: statSafe(abs).size, scope: scopeOf(root) });
        }
      }
    }
  }
  if (!instructionFiles.length) F.add('H02', 'instructions', 'gap', {});
  else F.add('H02', 'instructions', 'ok', { count: instructionFiles.length }, instructionFiles.map((i) => i.path));

  const projectInstruction = instructionFiles.filter((i) => i.scope === 'project');
  if (projectInstruction.length > 1) {
    F.add('H52', 'instructions', 'note', { count: projectInstruction.length }, projectInstruction.map((i) => i.path));
  }

  const sizeBudget = opts.instructionBudgetBytes;
  for (const i of instructionFiles) {
    if (i.bytes > sizeBudget) {
      F.add('H50', 'instructions', 'note', { bytes: i.bytes, budget: sizeBudget }, [i.path]);
      break;
    }
  }

  // Dead pointers. Only relative, project-rooted, path-shaped tokens are resolved; anything with a
  // runtime variable or a protocol is skipped rather than guessed at.
  const dead = [];
  let pointerChecked = 0;
  for (const i of instructionFiles) {
    const text = readTextSafe(i.path) || '';
    const seen = new Set();
    const re = /`([^`\n]{3,160})`/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const tok = m[1].trim();
      if (seen.has(tok)) continue;
      seen.add(tok);
      if (/^[a-z]+:\/\//i.test(tok)) continue;
      if (hasUnexpandedVar(tok)) continue;
      if (/\s/.test(tok)) continue;
      if (!/[\\/]/.test(tok)) continue;
      // Placeholders and elisions are illustrations, not paths. Counting them as dead pointers is
      // how a check earns a reputation for crying wolf, which costs more than the check is worth.
      if (/[<>]/.test(tok) || tok.includes('...') || tok.includes('*')) continue;
      const lower = tok.toLowerCase();
      const looksLikeFile = [...SCRIPT_EXT, ...ARTIFACT_EXT, '.toml', '.yaml', '.yml'].some((e) => lower.endsWith(e));
      const looksLikeDir = tok.endsWith('/') || tok.endsWith('\\');
      if (!looksLikeFile && !looksLikeDir) continue;
      if (path.isAbsolute(tok)) continue;
      // A pointer in an instruction file is written relative to that file, not to the project root,
      // and a leading ~ means the home directory. Resolving only against the project root reported
      // twelve live paths as dead on the first real setup this was pointed at.
      const trimmed = tok.replace(/[\\/]$/, '');
      const bases = trimmed.startsWith('~/') || trimmed.startsWith('~\\')
        ? [opts.osHome, homeDir]
        : [path.dirname(i.path), ...scanRoots];
      const target = trimmed.replace(/^~[\\/]/, '');
      pointerChecked++;
      const resolved = bases.some((b) => {
        const cand = path.resolve(b, target);
        return isFile(cand) || isDir(cand);
      });
      if (!resolved) dead.push({ pointer: tok, from: i.path });
    }
  }
  if (pointerChecked === 0) F.add('H51', 'instructions', 'unknown', { checked: 0 });
  else if (dead.length) F.add('H51', 'instructions', 'gap', { checked: pointerChecked, dead: dead.length }, dead.map((d) => d.pointer));
  else F.add('H51', 'instructions', 'ok', { checked: pointerChecked });

  /* --- settings -------------------------------------------------------------------------- */

  const settingsFiles = [];
  for (const d of detected) {
    for (const rel of d.profile.settingsFiles || []) {
      for (const { root, abs } of profilePaths(scanRoots, rel, d.profile)) {
        if (isFile(abs) && !settingsFiles.some((s) => s.path === abs)) {
          settingsFiles.push({ path: abs, scope: scopeOf(root), profile: d.profile });
        }
      }
    }
  }
  if (!settingsFiles.length) {
    F.add('H03', 'settings', 'gap', {});
  } else {
    F.add('H03', 'settings', 'ok', { count: settingsFiles.length }, settingsFiles.map((s) => s.path));
  }
  inventory.settings = settingsFiles.map((s) => s.path);

  const parsed = [];
  for (const s of settingsFiles) {
    const r = readJsonSafe(s.path);
    if (!r.ok) F.add('H04', 'settings', 'blocker', { reason: r.reason }, [s.path]);
    else parsed.push({ ...s, value: r.value });
  }
  if (settingsFiles.length && !F.has('H04')) F.add('H04', 'settings', 'ok', { parsed: parsed.length });

  /* --- hooks: declared, installed, resolvable -------------------------------------------- */

  let hooks = [];
  for (const p of parsed) {
    const hookRoot = p.value && typeof p.value === 'object' ? p.value[p.profile.hooksKey || 'hooks'] : null;
    for (const h of collectHooks(hookRoot, p.profile)) hooks.push({ ...h, from: p.path, profile: p.profile });
  }
  inventory.hooks = hooks.map((h) => ({ slot: h.slot, lifecycle: h.lifecycle, from: h.from, command: h.command }));

  const lifecycleClasses = ['sessionStart', 'preTool', 'postTool', 'sessionEnd'];
  const wired = new Set(hooks.map((h) => h.lifecycle));
  const missingSlots = lifecycleClasses.filter((c) => !wired.has(c));
  if (!hooks.length) F.add('H10', 'hooks', 'gap', { wired: 0, slots: lifecycleClasses });
  else if (missingSlots.length) F.add('H10', 'hooks', 'note', { wired: hooks.length, missing: missingSlots });
  else F.add('H10', 'hooks', 'ok', { wired: hooks.length });

  const roots = [...scanRoots, ...settingsFiles.map((s) => path.dirname(s.path))];
  const missingTargets = [];
  const unresolvable = [];
  let targetsChecked = 0;
  for (const h of hooks) {
    const tokens = hookTargets(h.command);
    if (!tokens.length) continue;
    for (const t of tokens) {
      if (hasUnexpandedVar(t)) {
        unresolvable.push({ slot: h.slot, token: t, from: h.from });
        continue;
      }
      targetsChecked++;
      if (!resolveCandidate(t, roots)) missingTargets.push({ slot: h.slot, token: t, from: h.from });
    }
  }
  if (missingTargets.length) {
    F.add('H11', 'hooks', 'blocker', { checked: targetsChecked, missing: missingTargets.length }, missingTargets.map((m) => `${m.slot}: ${m.token}`));
  } else if (targetsChecked > 0) {
    F.add('H11', 'hooks', 'ok', { checked: targetsChecked });
  } else if (hooks.length) {
    F.add('H11', 'hooks', 'unknown', { checked: 0, reason: 'no hook command named a script file this check could resolve' });
  }

  if (unresolvable.length) {
    F.add('H12', 'hooks', 'unknown', { count: unresolvable.length }, unresolvable.map((u) => `${u.slot}: ${u.token}`));
  }

  const noTimeout = hooks.filter((h) => h.timeout === null || h.timeout === undefined);
  if (hooks.length && noTimeout.length) {
    F.add('H13', 'hooks', 'note', { withoutTimeout: noTimeout.length, total: hooks.length });
  }

  /* --- evidence: does anything this harness declares actually leave a trace? -------------- */

  const evidenceCandidates = new Map();
  for (const h of hooks) {
    for (const t of pathLikeTokens(h.command, ARTIFACT_EXT)) {
      if (hasUnexpandedVar(t)) continue;
      const abs = path.isAbsolute(t) ? t : path.resolve(projectDir, t.replace(/^\.[\\/]/, ''));
      evidenceCandidates.set(abs, h.slot);
    }
  }
  for (const d of detected) {
    for (const rel of d.profile.evidenceDirs || []) {
      for (const { abs } of profilePaths(scanRoots, rel, d.profile)) {
        if (!isDir(abs)) continue;
        for (const f of walk(abs, { maxDepth: 2, skipDirs: ['node_modules', '.git'], maxEntries: 500 })) {
          if (ARTIFACT_EXT.some((e) => f.toLowerCase().endsWith(e))) evidenceCandidates.set(f, 'directory:' + rel);
        }
      }
    }
  }

  const evidenceFound = [];
  for (const [p, origin] of evidenceCandidates) {
    const st = statSafe(p);
    if (st && st.isFile()) evidenceFound.push({ path: p, origin, ageDays: daysSince(st.mtimeMs, nowMs), bytes: st.size });
  }
  inventory.evidence = evidenceFound;

  if (!hooks.length) {
    F.add('H20', 'evidence', 'unknown', { reason: 'no hooks declared, so there is nothing that should have left a trace' });
  } else if (!evidenceFound.length) {
    F.add('H20', 'evidence', 'gap', { hooks: hooks.length, artifacts: 0 });
  } else {
    F.add('H20', 'evidence', 'ok', { artifacts: evidenceFound.length });
    const fresh = evidenceFound.filter((e) => e.ageDays <= staleDays);
    if (!fresh.length) {
      const youngest = Math.min(...evidenceFound.map((e) => e.ageDays));
      F.add('H21', 'evidence', 'gap', { staleDays, youngestDays: youngest }, evidenceFound.slice(0, 5).map((e) => e.path));
    } else {
      F.add('H21', 'evidence', 'ok', { staleDays, fresh: fresh.length });
    }
  }

  /* --- fences ---------------------------------------------------------------------------- */

  const perms = { allow: [], deny: [], ask: [] };
  let permsSeen = false;
  for (const p of parsed) {
    const key = p.profile.permissionsKey || 'permissions';
    const node = p.value && typeof p.value === 'object' ? p.value[key] : null;
    if (node && typeof node === 'object') {
      permsSeen = true;
      for (const k of ['allow', 'deny', 'ask']) if (Array.isArray(node[k])) perms[k].push(...node[k]);
    }
  }
  if (!permsSeen) {
    F.add('H30', 'fences', 'unknown', { reason: 'no permission block found in any settings file this audit could read' });
  } else if (!perms.deny.length) {
    F.add('H30', 'fences', 'gap', { allow: perms.allow.length, deny: 0, ask: perms.ask.length });
  } else {
    F.add('H30', 'fences', 'ok', { allow: perms.allow.length, deny: perms.deny.length, ask: perms.ask.length });
  }

  // Deliberately narrow. A rule like Bash(git status:*) is a scoped wildcard and is not flagged;
  // flagging it would drown the real finding, which is a rule that grants a whole tool or everything.
  const BLANKET = /^(\*{1,2}|[A-Za-z_][A-Za-z0-9_]*\(\s*\*{1,2}\s*\))$/;
  const blanket = perms.allow.filter((a) => typeof a === 'string' && BLANKET.test(a.trim()));
  if (blanket.length) F.add('H31', 'fences', 'blocker', { count: blanket.length }, blanket);
  else if (permsSeen) F.add('H31', 'fences', 'ok', { count: 0 });

  if (permsSeen && !perms.ask.length) F.add('H33', 'fences', 'note', { ask: 0 });

  /* --- secret-shaped files ---------------------------------------------------------------- */

  // Two tiers, because one tier makes this check useless. A file called .env is a credential until
  // proved otherwise. A file whose name merely contains the word "credential" usually is not, and
  // reporting both at the same volume trains the reader to skip the section.
  const highRe = opts.secretPatterns.high.map((p) => new RegExp(p, 'i'));
  const lowRe = opts.secretPatterns.low.map((p) => new RegExp(p, 'i'));
  const exceptRe = (opts.secretPatterns.notCredentials || []).map((p) => new RegExp(p, 'i'));
  const skipDirs = opts.skipDirs;
  const projectFiles = walk(projectDir, { maxDepth: 4, skipDirs, maxEntries: 20000 });

  const classify = (f) => {
    const b = path.basename(f);
    if (exceptRe.some((re) => re.test(b))) return null;
    if (highRe.some((re) => re.test(b))) return 'high';
    if (lowRe.some((re) => re.test(b))) return 'low';
    return null;
  };
  const highFiles = [];
  const lowFiles = [];
  for (const f of projectFiles) {
    const t = classify(f);
    if (t === 'high') highFiles.push(f);
    else if (t === 'low') lowFiles.push(f);
  }

  const gitDir = path.join(projectDir, '.git');
  const ignoreCache = new Map();
  const rel = (f) => path.relative(projectDir, f).split(path.sep).join('/');

  if (!highFiles.length) {
    F.add('H32', 'fences', 'ok', { candidates: 0 });
  } else if (!isDir(gitDir)) {
    F.add('H32', 'fences', 'note', { candidates: highFiles.length, reason: 'not a git working tree' }, highFiles.map(rel));
  } else {
    const uncovered = highFiles.filter((f) => !gitignoreCovers(projectDir, f, ignoreCache));
    if (uncovered.length) {
      F.add('H32', 'fences', 'blocker', { candidates: highFiles.length, uncovered: uncovered.length }, uncovered.map(rel));
    } else {
      F.add('H32', 'fences', 'ok', { candidates: highFiles.length, uncovered: 0 });
    }
  }

  if (lowFiles.length) {
    const lowUncovered = isDir(gitDir) ? lowFiles.filter((f) => !gitignoreCovers(projectDir, f, ignoreCache)) : lowFiles;
    if (lowUncovered.length) F.add('H34', 'fences', 'note', { candidates: lowUncovered.length }, lowUncovered.map(rel));
  }

  /* --- unattended readiness ---------------------------------------------------------------- */

  const endHooks = hooks.filter((h) => h.lifecycle === 'sessionEnd');
  if (!hooks.length) F.add('H40', 'unattended', 'gap', { sessionEnd: 0 });
  else if (!endHooks.length) F.add('H40', 'unattended', 'gap', { sessionEnd: 0, wired: hooks.length });
  else F.add('H40', 'unattended', 'ok', { sessionEnd: endHooks.length });

  const signalDirs = [];
  for (const d of detected) {
    for (const rel of d.profile.signalDirs || []) {
      for (const { abs } of profilePaths(scanRoots, rel, d.profile)) {
        if (isDir(abs) && !signalDirs.includes(abs)) signalDirs.push(abs);
      }
    }
  }
  if (signalDirs.length) F.add('H41', 'unattended', 'ok', { dirs: signalDirs.length }, signalDirs);
  else F.add('H41', 'unattended', 'note', { dirs: 0 });

  const runLogs = evidenceFound.filter((e) => /\.(log|jsonl)$/i.test(e.path));
  if (runLogs.length) F.add('H42', 'unattended', 'ok', { logs: runLogs.length });
  else F.add('H42', 'unattended', 'gap', { logs: 0 });

  /* --- capability inventory ---------------------------------------------------------------- */

  let capTotal = 0;
  for (const d of detected) {
    for (const [label, rel] of Object.entries(d.profile.capabilityDirs || {})) {
      const seenDirs = new Set();
      for (const { root, abs } of profilePaths(scanRoots, rel, d.profile)) {
        if (!isDir(abs) || seenDirs.has(abs)) continue;
        seenDirs.add(abs);
        const entries = listDirSafe(abs).filter((e) => e.isDirectory() || e.isFile()).length;
        const key = `${label} (${scopeOf(root)})`;
        inventory.capabilities[key] = entries;
        capTotal += entries;
      }
    }
  }
  F.add('H60', 'inventory', capTotal ? 'ok' : 'note', { capabilities: capTotal, byLocation: inventory.capabilities });

  const telemetry = [];
  for (const d of detected) {
    for (const rel of d.profile.telemetryFiles || []) {
      for (const { abs } of profilePaths(scanRoots, rel, d.profile)) {
        if (isFile(abs) && !telemetry.includes(abs)) telemetry.push(abs);
      }
    }
  }
  if (capTotal && !telemetry.length) F.add('H61', 'inventory', 'unknown', { capabilities: capTotal, telemetry: 0 });
  else if (telemetry.length) F.add('H61', 'inventory', 'ok', { telemetry: telemetry.length }, telemetry);

  return { findings: F, inventory };
}

/* ------------------------------------------------------------------ redaction */

function makeRedactor(projectDir, homeDir, enabled) {
  if (!enabled) return (s) => s;
  const roots = [
    [path.resolve(projectDir), '<PROJECT>'],
    [path.resolve(homeDir), '<HOME>'],
  ];
  // A root is written three different ways in the material we scan, and a redactor that
  // knows only the first leaks through the other two. Native separators are what the OS
  // hands us; POSIX separators appear in config files authored by hand; the backslash-
  // doubled form is what any JSON blob carries once it has been through JSON.stringify,
  // which is how a Windows --redact run used to emit a clean Markdown report beside a
  // JSON record that still held the operator's home directory. Case-folding matters on
  // Windows for the same reason: the same directory is reachable as C:\Users and c:\users.
  const pairs = [];
  for (const [root, tag] of roots) {
    const forms = new Set([root, root.split(path.sep).join('/'), root.split('\\').join('\\\\')]);
    for (const form of forms) pairs.push([form, tag]);
  }
  pairs.sort((a, b) => b[0].length - a[0].length);
  const flags = process.platform === 'win32' ? 'gi' : 'g';
  const rules = pairs.map(([from, to]) => [new RegExp(from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), flags), to]);
  return (s) => {
    if (typeof s !== 'string') return s;
    let out = s;
    for (const [re, to] of rules) out = out.replace(re, to);
    return out;
  };
}

// Redact a structure by walking it, never by round-tripping it through JSON. Redacting a
// stringified blob applies the rules to text that has already been escaped, so nothing
// matches and the leak is silent. Keys are redacted too: an inventory keyed by path puts
// the path in the key, where a value-only walk would not look.
function redactDeep(value, redact) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, redact));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[redact(k)] = redactDeep(v, redact);
    return out;
  }
  return value;
}

// Every string anywhere inside a structure, for assertions that must see leaks the way a
// reader of the file would rather than the way JSON.stringify re-escapes them.
function deepStrings(value, acc = []) {
  if (typeof value === 'string') acc.push(value);
  else if (Array.isArray(value)) for (const v of value) deepStrings(v, acc);
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      acc.push(k);
      deepStrings(v, acc);
    }
  }
  return acc;
}

/* ------------------------------------------------------------------ rendering */

function renderMarkdown(result, ctx) {
  const { copy, redact } = ctx;
  const c = copy.checks;
  const counts = result.findings.counts();
  const L = [];
  const brandName = copy.brand.name;

  L.push(`# ${brandName}`);
  L.push('');
  L.push(copy.brand.line);
  L.push('');
  L.push(`**Scanned:** \`${redact(ctx.projectDir)}\`  `);
  L.push(`**Agent config:** \`${redact(ctx.homeDir)}\`  `);
  L.push(`**Run:** ${ctx.stamp} · engine ${TOOL_VERSION}${ctx.redacted ? ' · paths redacted' : ''}`);
  L.push('');
  L.push('---');
  L.push('');
  L.push('## What this run says');
  L.push('');
  L.push('| | count |');
  L.push('|---|---|');
  L.push(`| ${copy.severity.blocker.label} | ${counts.blocker} |`);
  L.push(`| ${copy.severity.gap.label} | ${counts.gap} |`);
  L.push(`| ${copy.severity.unknown.label} | ${counts.unknown} |`);
  L.push(`| ${copy.severity.note.label} | ${counts.note} |`);
  L.push(`| ${copy.severity.ok.label} | ${counts.ok} |`);
  L.push('');
  L.push(copy.report.readingRule);
  L.push('');

  const order = ['blocker', 'gap', 'unknown', 'note', 'ok'];
  for (const sev of order) {
    const rows = result.findings.rows.filter((r) => r.severity === sev);
    if (!rows.length) continue;
    L.push('---');
    L.push('');
    L.push(`## ${copy.severity[sev].heading}`);
    L.push('');
    L.push(copy.severity[sev].blurb);
    L.push('');
    for (const r of rows) {
      const entry = c[r.id] || {};
      const variant = entry.variants && entry.variants[r.severity] ? entry.variants[r.severity] : entry;
      L.push(`### ${r.id} · ${variant.title || entry.title || r.id}`);
      L.push('');
      if (variant.found) {
        L.push(`**What it found.** ${variant.found}`);
        L.push('');
      }
      const factLine = Object.entries(r.facts)
        .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
        .join(' · ');
      if (factLine) {
        L.push(`\`\`\``);
        L.push(redact(factLine));
        L.push(`\`\`\``);
        L.push('');
      }
      if (r.evidence && r.evidence.length) {
        L.push('Evidence:');
        L.push('');
        for (const e of r.evidence.slice(0, 12)) L.push(`- \`${redact(String(e))}\``);
        if (r.evidence.length > 12) L.push(`- ...and ${r.evidence.length - 12} more`);
        L.push('');
      }
      if (variant.cost) {
        L.push(`**What it costs.** ${variant.cost}`);
        L.push('');
      }
      if (variant.fix) {
        L.push(`**What closes it.** ${variant.fix}`);
        L.push('');
      }
      // A route never prints against a clear finding. There is nothing to close, so a pointer
      // here would be an advertisement wearing a finding's clothes, and one of those makes every
      // other route in the report worth less.
      //
      // And a route is written for one severity of one check, so it is keyed by both and prints
      // under neither of the others. Keyed by id alone, the pointer written for H11 reporting a
      // hook that names a missing file also printed under the same check reporting that it could
      // not tell, one line below that reading's own fix line, which says there is nothing to fix.
      // A severity nobody wrote a route for gets silence here, and so does a severity some later
      // version adds: the default is no pointer, and a pointer has to be asked for by name.
      const route = sev === 'ok' ? null : copy.routes && copy.routes[`${r.id}.${sev}`];
      if (route && String(route).trim()) {
        L.push(`**Where that lives.** ${route}`);
        L.push('');
      }
    }
  }

  L.push('---');
  L.push('');
  L.push('## Inventory');
  L.push('');
  L.push('| item | value |');
  L.push('|---|---|');
  L.push(`| harness families detected | ${result.inventory.profiles.map((p) => p.label).join(', ') || 'none'} |`);
  L.push(`| settings files read | ${result.inventory.settings.length} |`);
  L.push(`| hooks declared | ${result.inventory.hooks.length} |`);
  L.push(`| evidence artifacts found | ${result.inventory.evidence.length} |`);
  for (const [k, v] of Object.entries(result.inventory.capabilities)) L.push(`| ${k} | ${v} |`);
  L.push('');
  L.push('---');
  L.push('');
  L.push('## What this audit cannot tell you');
  L.push('');
  for (const lim of copy.report.limits) L.push(`- ${lim}`);
  L.push('');
  L.push(copy.report.footer);
  L.push('');
  return L.join('\n');
}

function renderJson(result, ctx) {
  const { redact } = ctx;
  return {
    tool: ctx.copy.brand.name,
    engine_version: TOOL_VERSION,
    generated: ctx.stamp,
    scanned: { project: redact(ctx.projectDir), agent_config: redact(ctx.homeDir), redacted: ctx.redacted },
    counts: result.findings.counts(),
    findings: result.findings.rows.map((r) => ({
      id: r.id,
      group: r.group,
      severity: r.severity,
      facts: redactDeep(r.facts, redact),
      evidence: r.evidence.map((e) => redact(String(e))),
    })),
    inventory: redactDeep(result.inventory, redact),
  };
}

/* ------------------------------------------------------------------ fixture materialisation */

function materialise(blueprint, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  for (const [rel, content] of Object.entries(blueprint.files)) {
    const full = path.join(destDir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    const body = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
    fs.writeFileSync(full, body, 'utf8');
  }
  for (const rel of blueprint.dirs || []) fs.mkdirSync(path.join(destDir, rel), { recursive: true });
  for (const [rel, ageDays] of Object.entries(blueprint.ages || {})) {
    const full = path.join(destDir, rel);
    if (fs.existsSync(full)) {
      const when = new Date(Date.now() - ageDays * 86400000);
      fs.utimesSync(full, when, when);
    }
  }
  return destDir;
}

function spawnCli(entrypoint, args, cwd) {
  return spawnSync(process.execPath, [entrypoint, ...args], {
    cwd,
    encoding: 'utf8',
    windowsHide: true,
  });
}

function copyPackage(destDir, omit = null) {
  fs.mkdirSync(destDir, { recursive: true });
  for (const name of ['MANIFEST.json', 'audit-copy.json', 'harness-audit.mjs', 'harness-profiles.json', 'README.md', 'REPORT-SHAPE.md', 'selftest-fixture.json']) {
    if (name !== omit) fs.copyFileSync(path.join(HERE, name), path.join(destDir, name));
  }
  return path.join(destDir, 'harness-audit.mjs');
}

function selfTest(ctx) {
  const say = (m) => console.log(`[harness-audit] ${m}`);
  const blueprints = ctx.fixture;
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'harness-audit-selftest-'));
  let failures = 0;
  const expect = (condition, message) => {
    if (condition) say(`  PASS ${message}`);
    else {
      say(`  FAIL ${message}`);
      failures++;
    }
  };
  try {
    // Production path, both halves. Each run launches this release entrypoint in a child
    // process, writes both reports, redacts fixture paths, and exercises the threshold.
    for (const half of ['broken', 'clean']) {
      const bp = blueprints[half];
      const dir = materialise(bp, path.join(tmpRoot, half));
      const out = path.join(tmpRoot, `${half}-out`);
      const run = spawnCli(ENTRYPOINT, ['--project', dir, '--home', dir, '--out', out, '--redact', '--fail-on', 'gap'], HERE);
      const expectedExit = half === 'broken' ? 1 : 0;
      expect(run.status === expectedExit, `half '${half}' production threshold exit is ${expectedExit} (found ${run.status})`);
      const mdPath = path.join(out, 'harness-audit-report.md');
      const jsonPath = path.join(out, 'harness-audit-report.json');
      expect(fs.existsSync(mdPath) && fs.existsSync(jsonPath), `half '${half}' wrote Markdown and JSON reports`);

      let record = null;
      let md = '';
      try {
        record = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
        md = fs.readFileSync(mdPath, 'utf8');
      } catch (e) {
        say(`  FAIL half '${half}' report rendering could not be read: ${e.message}`);
        failures++;
      }
      const actual = new Set((record?.findings ?? []).filter((r) => r.severity !== 'ok').map((r) => `${r.id}:${r.severity}`));
      const expected = new Set(bp.expect);
      const missed = [...expected].filter((e) => !actual.has(e));
      const extra = [...actual].filter((a) => !expected.has(a));
      say(`half '${half}': expected ${expected.size} finding(s), production CLI rendered ${actual.size}`);
      expect(missed.length === 0, `half '${half}' missed no expected finding${missed.length ? ` (${missed.join(', ')})` : ''}`);
      expect(extra.length === 0, `half '${half}' added no unexpected finding${extra.length ? ` (${extra.join(', ')})` : ''}`);
      const rendered = record?.engine_version === TOOL_VERSION && md.startsWith(`# ${ctx.copy.brand.name}\n`);
      expect(rendered, `half '${half}' rendered the ${TOOL_VERSION} report shape`);
      // Read the leak the way someone opening the file would. The assertion this replaces
      // re-stringified the already-parsed record and searched it for the unescaped path,
      // which an escaped blob can never contain: it passed on every run while the JSON
      // record leaked the full home directory. A privacy check that cannot fail is worse
      // than none, because it is reported as evidence.
      const needle = dir.toLowerCase();
      const leaked = deepStrings(record ?? {}).filter((s) => s.toLowerCase().includes(needle));
      expect(
        leaked.length === 0 && !md.includes(dir) && record?.scanned?.redacted === true,
        `half '${half}' redacted the fixture path${leaked.length ? ` — JSON leaked ${leaked.length} string(s), first: ${leaked[0]}` : ''}`,
      );

      // Must-accept control. Without --redact the same path has to appear in both reports.
      // Without this, "found no paths" cannot be distinguished from "there were no paths to
      // find", and the assertion above would pass just as happily on an empty file.
      const bareOut = `${out}-bare`;
      spawnCli(ENTRYPOINT, ['--project', dir, '--home', dir, '--out', bareOut], HERE);
      let bareRecord = null;
      try {
        bareRecord = JSON.parse(fs.readFileSync(path.join(bareOut, 'harness-audit-report.json'), 'utf8'));
      } catch { /* asserted below */ }
      const bareHits = deepStrings(bareRecord ?? {}).filter((s) => s.toLowerCase().includes(needle));
      expect(bareHits.length > 0, `half '${half}' control: unredacted JSON does contain the path (probe can detect a leak)`);
    }

    // Argument controls. The release entrypoint must refuse both an unknown option and a
    // bare operand. These launch the production file, not parseArgs in isolation.
    for (const bad of [['--unknown-option'], ['bare-operand']]) {
      const run = spawnCli(ENTRYPOINT, bad, HERE);
      expect(run.status === 3 && /CANNOT RUN: bad arguments/.test(run.stderr), `bad argument ${JSON.stringify(bad[0])} refuses with exit 3`);
    }

    // Delivery controls use isolated copies so the shipped tree is never modified.
    const malformedDir = path.join(tmpRoot, 'malformed-manifest-package');
    const malformedEntry = copyPackage(malformedDir);
    fs.writeFileSync(path.join(malformedDir, 'MANIFEST.json'), '{not-json', 'utf8');
    const malformed = spawnCli(malformedEntry, ['--version'], malformedDir);
    expect(malformed.status === 3 && /delivery verification failed/.test(malformed.stderr), 'malformed MANIFEST.json refuses before configuration is read');

    const missingDir = path.join(tmpRoot, 'missing-file-package');
    const missingEntry = copyPackage(missingDir, 'audit-copy.json');
    const missing = spawnCli(missingEntry, ['--version'], missingDir);
    expect(missing.status === 3 && /listed file is missing or unreadable: audit-copy.json/.test(missing.stderr), 'missing manifest-listed file refuses before configuration is read');
  } finally {
    try {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    } catch {
      /* leaving a temp dir behind is not worth failing a self-test over */
    }
  }
  if (failures) {
    say('SELF-TEST FAIL');
    return 3;
  }
  say('SELF-TEST PASS  (a planted-defect harness reported exactly its defects; a clean one reported none of them)');
  return 0;
}

/* ------------------------------------------------------------------ cli */

function parseArgs(argv) {
  const flagNames = new Set(['help', 'version', 'redact', 'self-test']);
  const valueNames = new Set(['project', 'home', 'out', 'stale-days', 'fail-on', 'emit-fixture']);
  const a = { flags: new Set(), values: {} };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (!t.startsWith('--')) throw new Error(`bare operand is not accepted: ${t}`);
    const key = t.slice(2);
    if (!key || t.includes('=')) throw new Error(`unsupported token: ${t}`);
    if (!flagNames.has(key) && !valueNames.has(key)) throw new Error(`unknown option: ${t}`);
    if (a.flags.has(key) || Object.prototype.hasOwnProperty.call(a.values, key)) throw new Error(`duplicate option: ${t}`);
    if (flagNames.has(key)) {
      a.flags.add(key);
      continue;
    }
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) throw new Error(`${t} requires one value`);
    a.values[key] = next;
    i++;
  }

  const actions = ['help', 'version', 'self-test'].filter((key) => a.flags.has(key));
  if (a.values['emit-fixture']) actions.push('emit-fixture');
  if (actions.length > 1) throw new Error(`choose one action, not ${actions.join(', ')}`);
  if (actions.length === 1 && argv.length !== (actions[0] === 'emit-fixture' ? 2 : 1)) {
    throw new Error(`--${actions[0]} cannot be combined with audit options`);
  }
  if (a.values['stale-days'] !== undefined && (!/^\d+$/.test(a.values['stale-days']) || Number(a.values['stale-days']) < 1)) {
    throw new Error('--stale-days must be a positive integer');
  }
  if (a.values['fail-on'] !== undefined && !['none', 'note', 'unknown', 'gap', 'blocker'].includes(a.values['fail-on'].toLowerCase())) {
    throw new Error('--fail-on must be one of none, note, unknown, gap, blocker');
  }
  return a;
}

function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(`[harness-audit] CANNOT RUN: bad arguments: ${e.message}`);
    process.exit(3);
  }

  const delivery = verifyDelivery();
  if (!delivery.ok) process.exit(deliveryFailure(delivery.reason));

  const copyRes = readJsonSafe(path.join(HERE, 'audit-copy.json'));
  const profRes = readJsonSafe(path.join(HERE, 'harness-profiles.json'));
  const fixRes = readJsonSafe(path.join(HERE, 'selftest-fixture.json'));
  for (const [name, r] of [['audit-copy.json', copyRes], ['harness-profiles.json', profRes], ['selftest-fixture.json', fixRes]]) {
    if (!r.ok) {
      console.error(`[harness-audit] CANNOT RUN: ${name} ${r.reason}`);
      process.exit(3);
    }
  }
  const copy = copyRes.value;
  const cfg = profRes.value;

  if (args.flags.has('version')) {
    console.log(`${copy.brand.name} engine ${TOOL_VERSION} (${delivery.checked}/${DELIVERY_FILE_COUNT} delivery files verified)`);
    process.exit(0);
  }
  if (args.flags.has('help')) {
    console.log(copy.cli.help);
    process.exit(0);
  }

  const projectDir = path.resolve(args.values.project || process.cwd());
  const homeDir = path.resolve(args.values.home || os.homedir());
  const staleDays = Number(args.values['stale-days'] || cfg.defaults.staleDays);
  const nowMs = Date.now();

  const ctx = {
    projectDir,
    homeDir,
    osHome: os.homedir(),
    staleDays,
    nowMs,
    profiles: cfg.profiles,
    secretPatterns: cfg.defaults.secretPatterns,
    skipDirs: cfg.defaults.skipDirs,
    instructionBudgetBytes: cfg.defaults.instructionBudgetBytes,
    copy,
    fixture: fixRes.value,
  };

  if (args.values['emit-fixture']) {
    const dest = path.resolve(args.values['emit-fixture']);
    for (const half of ['broken', 'clean']) materialise(fixRes.value[half], path.join(dest, half));
    fs.writeFileSync(
      path.join(dest, 'EXPECTED.json'),
      JSON.stringify({ broken: fixRes.value.broken.expect, clean: fixRes.value.clean.expect }, null, 2),
      'utf8'
    );
    console.log(`[harness-audit] fixture written to ${dest}`);
    process.exit(0);
  }

  if (args.flags.has('self-test')) process.exit(selfTest(ctx));

  if (!isDir(projectDir)) {
    console.error(`[harness-audit] CANNOT RUN: --project is not a directory: ${projectDir}`);
    process.exit(3);
  }

  const result = runAudit(ctx);
  const redacted = args.flags.has('redact');
  const renderCtx = {
    ...ctx,
    redact: makeRedactor(projectDir, homeDir, redacted),
    redacted,
    stamp: new Date(nowMs).toISOString().replace('T', ' ').slice(0, 19) + 'Z',
  };

  const outDir = path.resolve(args.values.out || process.cwd());
  fs.mkdirSync(outDir, { recursive: true });
  const mdPath = path.join(outDir, cfg.defaults.reportBasename + '.md');
  const jsonPath = path.join(outDir, cfg.defaults.reportBasename + '.json');
  fs.writeFileSync(mdPath, renderMarkdown(result, renderCtx), 'utf8');
  fs.writeFileSync(jsonPath, JSON.stringify(renderJson(result, renderCtx), null, 2), 'utf8');

  const counts = result.findings.counts();
  console.log(
    `[harness-audit] ${counts.blocker} blocker, ${counts.gap} gap, ${counts.unknown} unknown, ${counts.note} note, ${counts.ok} clear`
  );
  console.log(`[harness-audit] report -> ${mdPath}`);
  console.log(`[harness-audit] record -> ${jsonPath}`);

  const failOn = (args.values['fail-on'] || 'none').toLowerCase();
  if (failOn !== 'none') {
    const threshold = rank(failOn);
    if (threshold < 0) {
      console.error(`[harness-audit] CANNOT RUN: --fail-on must be one of none, note, unknown, gap, blocker`);
      process.exit(3);
    }
    const hit = result.findings.rows.some((r) => r.severity !== 'ok' && rank(r.severity) >= threshold);
    if (hit) {
      console.log(`[harness-audit] --fail-on ${failOn} was met`);
      process.exit(1);
    }
  }
  process.exit(0);
}

main();
