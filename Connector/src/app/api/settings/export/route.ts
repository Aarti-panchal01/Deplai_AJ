import { NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { query, type DbRow } from '@/lib/db';
import { buildUserExport, exportFilename } from '@/lib/settings-export';
import { parseStoredUserSettings, toPublicUserSettings } from '@/lib/user-settings';

function parseJson(value: unknown): unknown {
  if (value && typeof value === 'object') return value;
  if (typeof value !== 'string') return {};
  try {
    return JSON.parse(value);
  } catch {
    return {};
  }
}

/**
 * Settings → Privacy & Data → "Export my data".
 * Returns the signed-in user's own records as a JSON download. Secrets in settings are replaced
 * by "has…" flags (via toPublicUserSettings); server file paths are dropped.
 */
export async function GET() {
  const { user, error } = await requireAuth();
  if (error) return error;

  try {
    const [accountRows, settingsRows, projects, installations, chatSessions] = await Promise.all([
      query<DbRow[]>('SELECT id, email, name, created_at FROM users WHERE id = ? LIMIT 1', [user.id]),
      query<DbRow[]>('SELECT data_json FROM user_settings WHERE user_id = ? LIMIT 1', [user.id]).catch(() => [] as DbRow[]),
      query<DbRow[]>(
        `SELECT id, name, project_type, repository_id, local_path, file_count, size_bytes, created_at
         FROM projects WHERE user_id = ? ORDER BY created_at`,
        [user.id]
      ),
      query<DbRow[]>(
        `SELECT id, installation_id, account_login, account_type, installed_at, suspended_at, created_at
         FROM github_installations WHERE user_id = ? ORDER BY installed_at`,
        [user.id]
      ),
      query<DbRow[]>(
        `SELECT id, title, message_count, created_at, updated_at
         FROM chat_sessions WHERE user_id = ? ORDER BY created_at`,
        [user.id]
      ),
    ]);

    const installationIds = installations.map((row) => String(row.id));
    const sessionIds = chatSessions.map((row) => String(row.id));

    const repositories = installationIds.length
      ? await query<DbRow[]>(
          `SELECT id, installation_id, github_repo_id, full_name, default_branch, is_private, last_synced_at, created_at
           FROM github_repositories WHERE installation_id IN (${installationIds.map(() => '?').join(',')})
           ORDER BY full_name`,
          installationIds
        )
      : [];
    const chatMessages = sessionIds.length
      ? await query<DbRow[]>(
          `SELECT id, session_id, role, content, created_at
           FROM chat_messages WHERE session_id IN (${sessionIds.map(() => '?').join(',')})
           ORDER BY created_at`,
          sessionIds
        )
      : [];

    const now = new Date();
    const stored = settingsRows[0]?.data_json;
    const payload = buildUserExport({
      account: accountRows[0] ?? null,
      settings: stored ? toPublicUserSettings(parseStoredUserSettings(parseJson(stored))) : null,
      projects,
      installations,
      repositories,
      chatSessions,
      chatMessages,
      now,
    });

    return new NextResponse(JSON.stringify(payload, null, 2), {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${exportFilename(now, user.login)}"`,
        'Cache-Control': 'no-store',
      },
    });
  } catch {
    return NextResponse.json({ error: 'Failed to export your data' }, { status: 500 });
  }
}
