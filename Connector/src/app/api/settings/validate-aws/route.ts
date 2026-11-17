import { NextRequest, NextResponse } from 'next/server';
import { hasWorkspaceAdminAccess, requireAuth } from '@/lib/auth';
import { AGENTIC_URL, agenticHeaders } from '@/lib/agentic';

/**
 * Settings → Cloud → "Validate credentials".
 * Asks the Agentic Layer to call STS GetCallerIdentity (read-only). Credentials typed into the
 * form are validated as-is and never stored by this route. With no credentials in the body, the
 * server's own AWS environment credentials are checked, which requires workspace admin access.
 */
export async function POST(request: NextRequest) {
  const { user, error } = await requireAuth();
  if (error) return error;

  const body = await request.json().catch(() => ({})) as {
    accessKeyId?: unknown;
    secretAccessKey?: unknown;
    region?: unknown;
  };
  const accessKeyId = typeof body.accessKeyId === 'string' ? body.accessKeyId.trim() : '';
  const secretAccessKey = typeof body.secretAccessKey === 'string' ? body.secretAccessKey.trim() : '';
  const region = typeof body.region === 'string' && /^[a-z]{2}(-[a-z]+)+-\d$/.test(body.region.trim())
    ? body.region.trim()
    : 'us-east-1';

  if (Boolean(accessKeyId) !== Boolean(secretAccessKey)) {
    return NextResponse.json({ valid: false, error: 'Enter both the access key ID and the secret access key.' });
  }

  if (!accessKeyId) {
    const isAdmin = await hasWorkspaceAdminAccess(user, request.headers.get('x-workspace-admin-key'));
    if (!isAdmin) {
      return NextResponse.json({ valid: false, error: 'Enter an access key ID and secret access key to validate.' });
    }
    if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) {
      return NextResponse.json({ valid: false, error: 'No AWS credentials are configured on the server and none were entered.' });
    }
  }

  try {
    const response = await fetch(`${AGENTIC_URL}/api/aws/validate-credentials`, {
      method: 'POST',
      headers: agenticHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        aws_access_key_id: accessKeyId,
        aws_secret_access_key: secretAccessKey,
        aws_region: region,
      }),
      signal: AbortSignal.timeout(20000),
    });
    if (!response.ok) {
      return NextResponse.json({ valid: false, error: `Validation service returned HTTP ${response.status}.` });
    }
    const result = await response.json() as { valid?: boolean; account?: string | null; arn?: string | null; error?: string | null };
    return NextResponse.json({
      valid: Boolean(result.valid),
      account: result.account ?? null,
      arn: result.arn ?? null,
      error: result.error ?? null,
    });
  } catch {
    return NextResponse.json({ valid: false, error: 'The validation service (Agentic Layer) is unreachable.' });
  }
}
