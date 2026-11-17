import { randomBytes } from 'crypto';
import { NextResponse } from 'next/server';
import { getIronSession } from 'iron-session';
import { cookies } from 'next/headers';
import { requireEnv } from '@/lib/env';
import { getSessionOptions, type SessionData } from '@/lib/session';

const LOGOUT_GUARD_COOKIE = 'deplai_recent_logout';

function setupNeededResponse(missing: string[]) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>DeplAI sign-in not configured</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#e5e5e5;max-width:640px;margin:12vh auto;padding:0 24px;line-height:1.55}
code{background:#1f1f1f;padding:2px 6px;border-radius:4px}a{color:#8ab4ff}</style></head><body>
<h1>GitHub sign-in is not configured</h1>
<p>DeplAI signs users in with a GitHub OAuth App. These environment variables are empty: ${missing.map((m) => `<code>${m}</code>`).join(', ')}.</p>
<ol><li>Create an OAuth App at <a href="https://github.com/settings/developers">GitHub &rarr; Settings &rarr; Developer settings</a> with the callback URL <code>/api/auth/callback</code> on this app's origin.</li>
<li>Put its client ID and secret in the repository <code>.env</code> as <code>GITHUB_CLIENT_ID</code> and <code>GITHUB_CLIENT_SECRET</code>.</li>
<li>Restart the Connector.</li></ol>
<p><a href="/">&larr; Back to the landing page</a></p></body></html>`;
  return new NextResponse(html, { status: 503, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

export async function GET(request: Request) {
  const missing = ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'].filter((name) => !process.env[name]?.trim());
  if (missing.length > 0) {
    return setupNeededResponse(missing);
  }

  const cookieStore = await cookies();
  const session = await getIronSession<SessionData>(cookieStore, getSessionOptions());
  const { searchParams } = new URL(request.url);
  const logoutGuardCookie = cookieStore.get(LOGOUT_GUARD_COOKIE)?.value;
  const isForcedLogin = searchParams.get('force') === '1';

  if (logoutGuardCookie && !isForcedLogin) {
    return NextResponse.redirect(`${requireEnv('NEXT_PUBLIC_APP_URL')}/?logged_out=1`, 302);
  }

  if (logoutGuardCookie && isForcedLogin) {
    cookieStore.delete(LOGOUT_GUARD_COOKIE);
  }

  const state = randomBytes(32).toString('hex');
  session.oauthState = state;
  session.oauthStateExpiresAt = Date.now() + (10 * 60 * 1000);
  await session.save();

  const params = new URLSearchParams({
    client_id: requireEnv('GITHUB_CLIENT_ID'),
    redirect_uri: `${requireEnv('NEXT_PUBLIC_APP_URL')}/api/auth/callback`,
    scope: 'user:email read:user read:org',
    state,
    // Do not silently reuse the last GitHub browser session. This lets a user
    // deliberately choose another account after signing out of Deplai.
    prompt: 'select_account',
  });

  return NextResponse.redirect(`https://github.com/login/oauth/authorize?${params}`, 302);
}
