import { describe, expect, test } from 'bun:test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import * as freshnessApi from '../src/freshness/index.ts';
import * as httpApi from '../src/http/index.ts';
import * as rootApi from '../src/index.ts';
import * as processApi from '../src/process/index.ts';
import * as scrubApi from '../src/scrub/index.ts';
import * as websocketApi from '../src/websocket/index.ts';

const ROOT = join(import.meta.dir, '..');

const ENTRYPOINTS = [
  { file: 'src/index.ts', mod: rootApi },
  { file: 'src/scrub/index.ts', mod: scrubApi },
  { file: 'src/http/index.ts', mod: httpApi },
  { file: 'src/process/index.ts', mod: processApi },
  { file: 'src/websocket/index.ts', mod: websocketApi },
  { file: 'src/freshness/index.ts', mod: freshnessApi },
] as const;

const parseExportedSymbols = (source: string): string[] => {
  const names: string[] = [];
  const blockPattern = /export\s+(?:type\s+)?\{([^}]+)\}\s*from\s*['"][^'"]+['"]/g;
  for (const match of source.matchAll(blockPattern)) {
    const body = match[1] ?? '';
    for (const rawEntry of body.split(',')) {
      const cleaned = rawEntry
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/\/\/.*$/gm, '')
        .trim();
      if (!cleaned) continue;
      const withoutType = cleaned.replace(/^type\s+/, '').trim();
      const parts = withoutType.split(/\s+as\s+/);
      const exportedName = (parts[1] ?? parts[0] ?? '').trim();
      if (exportedName) names.push(exportedName);
    }
  }
  return names;
};

const walkFiles = (dir: string): string[] =>
  readdirSync(dir).flatMap((name) => {
    const fullPath = join(dir, name);
    if (statSync(fullPath).isDirectory()) return walkFiles(fullPath);
    return [relative(ROOT, fullPath)];
  });

describe('verbs and vocabulary', () => {
  const verbsDoc = readFileSync(join(ROOT, 'docs/VERBS.md'), 'utf8');

  test('every exported symbol (runtime + types) across all six entry points is documented in docs/VERBS.md', () => {
    const allExported = new Set<string>();
    for (const entry of ENTRYPOINTS) {
      for (const name of Object.keys(entry.mod)) allExported.add(name);
      const source = readFileSync(join(ROOT, entry.file), 'utf8');
      for (const name of parseExportedSymbols(source)) allExported.add(name);
    }
    const missing = [...allExported].filter((name) => !verbsDoc.includes(`\`${name}\``)).sort();
    expect(missing).toEqual([]);
  });

  test('no stale or removed symbol names remain in docs/VERBS.md tables/lists', () => {
    const allExported = new Set<string>();
    for (const entry of ENTRYPOINTS) {
      for (const name of Object.keys(entry.mod)) allExported.add(name);
      const source = readFileSync(join(ROOT, entry.file), 'utf8');
      for (const name of parseExportedSymbols(source)) allExported.add(name);
    }

    const documentedSymbols = new Set<string>();
    const lines = verbsDoc.split('\n');
    let inConstantsList = false;
    for (const line of lines) {
      const tableMatch = line.match(/^\|\s*[^|]+\|\s*`([A-Za-z_][A-Za-z0-9_]*)`\s*\|/);
      if (tableMatch?.[1]) {
        documentedSymbols.add(tableMatch[1]);
        continue;
      }
      if (/^(Constants and registries|Constants):/.test(line)) {
        inConstantsList = true;
      } else if (line.trim() === '') {
        inConstantsList = false;
      }
      if (inConstantsList) {
        for (const match of line.matchAll(/`([A-Za-z_][A-Za-z0-9_]*)`/g)) {
          if (match[1]) documentedSymbols.add(match[1]);
        }
      }
    }
    const typesSection = verbsDoc.split('## Exported Types')[1] ?? '';
    for (const match of typesSection.matchAll(/`([A-Za-z_][A-Za-z0-9_]*)`/g)) {
      if (match[1]) documentedSymbols.add(match[1]);
    }

    const stale = [...documentedSymbols].filter((name) => !allExported.has(name)).sort();
    expect(stale).toEqual([]);
  });

  test('no public export starts with the banned get* prefix (R-2026-11-17-07)', () => {
    const exported = new Set<string>();
    for (const entry of ENTRYPOINTS) {
      for (const name of Object.keys(entry.mod)) exported.add(name);
      const source = readFileSync(join(ROOT, entry.file), 'utf8');
      for (const name of parseExportedSymbols(source)) exported.add(name);
    }
    const offenders = [...exported].filter((name) => /^get[A-Z]/.test(name));
    expect(offenders).toEqual([]);
  });

  test('no closed-product names leak into public MIT src/, README.md, or docs/VERBS.md', () => {
    const forbidden = /\b(chorus|oracle|warden|herald|prospector)\b/i;
    const filesToCheck = [...walkFiles(join(ROOT, 'src')), 'README.md', 'docs/VERBS.md'];
    const hits = filesToCheck.filter((relPath) =>
      forbidden.test(readFileSync(join(ROOT, relPath), 'utf8')),
    );
    expect(hits).toEqual([]);
  });
});
