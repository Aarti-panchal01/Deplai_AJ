import { NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { errorMessage, errorStatus } from '@/lib/errors';
import { githubService } from '@/lib/github';

/**
 * Settings → GitHub App → "Test connection".
 * Authenticates as the configured GitHub App and returns only public App metadata
 * (name, slug, id, permissions, subscribed events). Secrets are never returned.
 */
export async function POST() {
  const { error } = await requireAuth();
  if (error) return error;

  const missing = ['GITHUB_APP_ID', 'GITHUB_PRIVATE_KEY'].filter((name) => !process.env[name]?.trim());
  if (missing.length > 0) {
    return NextResponse.json({
      ok: false,
      error: `GitHub App is not configured on the server (missing ${missing.join(', ')}).`,
    });
  }

  try {
    const app = await githubService.getAppInfo();
    return NextResponse.json({ ok: true, app });
  } catch (err: unknown) {
    const status = errorStatus(err);
    const message =
      status === 401
        ? 'GitHub rejected the App ID / private key. Check GITHUB_APP_ID and GITHUB_PRIVATE_KEY.'
        : `Could not reach the GitHub App: ${errorMessage(err).slice(0, 200)}`;
    return NextResponse.json({ ok: false, error: message });
  }
}
