import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildUserExport, exportFilename } from './settings-export.ts';

const base = {
  account: { id: 'u1', email: 'a@example.com' },
  settings: { ai: { hasApiKey: true } },
  projects: [{ id: 'p1', name: 'demo', local_path: '/srv/uploads/u1/p1' }],
  installations: [{ id: 'i1', account_login: 'octo' }, { id: 'i2', account_login: 'other' }],
  repositories: [
    { id: 'r1', installation_id: 'i1', full_name: 'octo/a' },
    { id: 'r2', installation_id: 'i1', full_name: 'octo/b' },
  ],
  chatSessions: [{ id: 's1', title: 'hello' }],
  chatMessages: [
    { id: 'm1', session_id: 's1', role: 'user', content: 'hi' },
    { id: 'm2', session_id: 's1', role: 'assistant', content: 'hello' },
    { id: 'm3', session_id: 'orphan', role: 'user', content: 'lost' },
  ],
  now: new Date('2026-11-17T10:00:00Z'),
};

test('groups repositories under their installation and messages under their session', () => {
  const out = buildUserExport(base);
  assert.equal(out.github.installations[0].repositories.length, 2);
  assert.equal(out.github.installations[1].repositories.length, 0);
  assert.deepEqual(out.chat.sessions[0].messages.map((m) => m.id), ['m1', 'm2']);
});

test('drops server filesystem paths from projects', () => {
  const out = buildUserExport(base);
  assert.equal('local_path' in out.projects[0], false);
  assert.equal(out.projects[0].name, 'demo');
});

test('reports accurate counts, including rows that matched no parent', () => {
  const out = buildUserExport(base);
  assert.deepEqual(out.counts, { projects: 1, installations: 2, repositories: 2, chatSessions: 1, chatMessages: 3 });
});

test('stamps format and time, and does not mutate the input', () => {
  const copy = structuredClone(base);
  const out = buildUserExport(base);
  assert.equal(out.format, 'deplai-user-export-v1');
  assert.equal(out.exportedAt, '2026-11-17T10:00:00.000Z');
  assert.deepEqual(base, copy);
});

test('empty account still exports', () => {
  const out = buildUserExport({ ...base, account: null, projects: [], installations: [], repositories: [], chatSessions: [], chatMessages: [] });
  assert.equal(out.account, null);
  assert.equal(out.counts.projects, 0);
});

test('filename is date-stamped and strips unsafe characters from the login', () => {
  assert.equal(exportFilename(new Date('2026-11-17T23:59:00Z'), 'octo-cat'), 'deplai-export-octo-cat-2026-11-17.json');
  assert.equal(exportFilename(new Date('2026-11-17T00:00:00Z'), '../etc/passwd'), 'deplai-export-etcpasswd-2026-11-17.json');
  assert.equal(exportFilename(new Date('2026-11-17T00:00:00Z'), null), 'deplai-export-user-2026-11-17.json');
});
