/**
 * Pure helpers for the Settings "Export my data" download. No I/O, no framework imports,
 * so it can be unit-tested with `node --test`.
 */

export type Row = Record<string, unknown>;

export interface UserExportInput {
  account: Row | null;
  /** Already sanitised settings (secrets replaced by "has..." flags). */
  settings: unknown;
  projects: Row[];
  installations: Row[];
  repositories: Row[];
  chatSessions: Row[];
  chatMessages: Row[];
  now?: Date;
}

export interface UserExport {
  format: 'deplai-user-export-v1';
  exportedAt: string;
  account: Row | null;
  settings: unknown;
  projects: Row[];
  github: { installations: Array<Row & { repositories: Row[] }> };
  chat: { sessions: Array<Row & { messages: Row[] }> };
  counts: { projects: number; installations: number; repositories: number; chatSessions: number; chatMessages: number };
}

function groupBy(rows: Row[], key: string): Map<string, Row[]> {
  const groups = new Map<string, Row[]>();
  for (const row of rows) {
    const id = String(row[key] ?? '');
    const list = groups.get(id);
    if (list) list.push(row);
    else groups.set(id, [row]);
  }
  return groups;
}

export function buildUserExport(input: UserExportInput): UserExport {
  const reposByInstallation = groupBy(input.repositories, 'installation_id');
  const messagesBySession = groupBy(input.chatMessages, 'session_id');

  return {
    format: 'deplai-user-export-v1',
    exportedAt: (input.now ?? new Date()).toISOString(),
    account: input.account,
    settings: input.settings,
    // local_path is a server filesystem path, not user data.
    projects: input.projects.map((project) => {
      const copy = { ...project };
      delete copy.local_path;
      return copy;
    }),
    github: {
      installations: input.installations.map((installation) => ({
        ...installation,
        repositories: reposByInstallation.get(String(installation.id ?? '')) ?? [],
      })),
    },
    chat: {
      sessions: input.chatSessions.map((session) => ({
        ...session,
        messages: messagesBySession.get(String(session.id ?? '')) ?? [],
      })),
    },
    counts: {
      projects: input.projects.length,
      installations: input.installations.length,
      repositories: input.repositories.length,
      chatSessions: input.chatSessions.length,
      chatMessages: input.chatMessages.length,
    },
  };
}

export function exportFilename(now: Date, login?: string | null): string {
  const safeLogin = String(login ?? '').replace(/[^a-zA-Z0-9_-]/g, '') || 'user';
  return `deplai-export-${safeLogin}-${now.toISOString().slice(0, 10)}.json`;
}
