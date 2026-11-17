'use client';

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Image from 'next/image';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Cloud,
  Cpu,
  Database,
  Eye,
  EyeOff,
  Github,
  Key,
  Laptop,
  Loader2,
  Lock,
  Network,
  RefreshCw,
  Save,
  Shield,
  User,
} from 'lucide-react';
import { LLM_PROVIDERS, useLLM, type LLMProvider } from '@/lib/llm-context';

type HealthState = 'healthy' | 'degraded' | 'down';
type ContextKey = 'workspace' | 'user';
type WorkspaceTabKey = 'integrations' | 'cloud' | 'ai' | 'secrets' | 'danger';
type UserTabKey = 'account' | 'security' | 'privacy' | 'billing' | 'sessions';
type TabKey = WorkspaceTabKey | UserTabKey;

type PublicSettings = {
  integrations: {
    githubAppActive: boolean;
    githubAppId: string;
    hasGithubPrivateKey: boolean;
    hasWebhookSecret: boolean;
  };
  cloud: {
    defaultRegion: string;
    monthlyBudgetUsd: number;
    budgetOverride: boolean;
    hasAwsAccessKeyId: boolean;
    hasAwsSecretAccessKey: boolean;
  };
  ai: {
    provider: LLMProvider;
    model: string;
    hasApiKey: boolean;
    maxExecutionCycles: number;
    autoApproveLow: boolean;
  };
  workspace: {
    hasServiceKey: boolean;
    hasSessionSecret: boolean;
    hasWsTokenSecret: boolean;
  };
};

type ServerConfig = {
  githubAppConfigured: boolean;
  githubWebhookConfigured: boolean;
  awsRuntimeConfigured: boolean;
  sessionSecretConfigured: boolean;
  serviceKeyConfigured: boolean;
  cleanupEnabled: boolean;
};

type SettingsResponse = {
  settings: PublicSettings;
  serverConfig: ServerConfig;
  updatedAt: string | null;
  success?: boolean;
  error?: string;
};

type ProjectsResponse = {
  projects?: Array<{ id: string }>;
};

type InstallationsResponse = {
  installations?: Array<{ id: string }>;
};

type HealthResponse = {
  overall?: HealthState;
  checks?: Array<{
    name?: string;
    state?: HealthState;
    detail?: string;
  }>;
};

type LiveMetrics = {
  projectCount: number;
  installationCount: number;
  healthOverall: HealthState | 'unknown';
  checks: Array<{ name: string; state: HealthState; detail: string }>;
  lastRefreshedAt: string | null;
};

type SecretDrafts = {
  githubPrivateKey: string;
  webhookSecret: string;
  awsAccessKeyId: string;
  awsSecretAccessKey: string;
  aiApiKey: string;
  serviceKey: string;
  sessionSecret: string;
  wsTokenSecret: string;
};

const T = {
  bg: 'bg-[#0A0B0F]',
  surface: 'bg-[#111318]',
  border: 'border-[#1E2028]',
  text: 'text-zinc-100',
  muted: 'text-zinc-400',
  hint: 'text-zinc-500',
  mono: 'font-mono text-zinc-300',
};

const DEFAULT_SETTINGS: PublicSettings = {
  integrations: {
    githubAppActive: true,
    githubAppId: '',
    hasGithubPrivateKey: false,
    hasWebhookSecret: false,
  },
  cloud: {
    defaultRegion: 'us-east-1',
    monthlyBudgetUsd: 100,
    budgetOverride: false,
    hasAwsAccessKeyId: false,
    hasAwsSecretAccessKey: false,
  },
  ai: {
    provider: 'claude',
    model: 'claude-opus-4-5',
    hasApiKey: false,
    maxExecutionCycles: 2,
    autoApproveLow: false,
  },
  workspace: {
    hasServiceKey: false,
    hasSessionSecret: false,
    hasWsTokenSecret: false,
  },
};

const DEFAULT_SERVER_CONFIG: ServerConfig = {
  githubAppConfigured: false,
  githubWebhookConfigured: false,
  awsRuntimeConfigured: false,
  sessionSecretConfigured: false,
  serviceKeyConfigured: false,
  cleanupEnabled: false,
};

const DEFAULT_LIVE: LiveMetrics = {
  projectCount: 0,
  installationCount: 0,
  healthOverall: 'unknown',
  checks: [],
  lastRefreshedAt: null,
};

const DEFAULT_SECRET_DRAFTS: SecretDrafts = {
  githubPrivateKey: '',
  webhookSecret: '',
  awsAccessKeyId: '',
  awsSecretAccessKey: '',
  aiApiKey: '',
  serviceKey: '',
  sessionSecret: '',
  wsTokenSecret: '',
};

const REGION_OPTIONS = ['us-east-1', 'us-west-2', 'eu-central-1', 'eu-west-1', 'ap-south-1', 'ap-southeast-1'];

const PROVIDER_MODELS: Record<LLMProvider, string[]> = {
  claude: ['claude-opus-4-5', 'claude-sonnet-4-0', 'claude-3-5-sonnet'],
  openai: ['gpt-4o', 'gpt-4.1', 'o4-mini'],
  gemini: ['gemini-2.5-pro', 'gemini-2.0-flash', 'gemini-1.5-pro'],
  groq: ['llama-3.3-70b-versatile', 'mixtral-8x7b-32768', 'llama3-70b-8192'],
  openrouter: ['anthropic/claude-opus-4-5', 'openai/gpt-4o', 'google/gemini-2.5-pro'],
};

const WORKSPACE_TABS: Array<{ id: WorkspaceTabKey; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: 'integrations', label: 'Integrations', icon: Github },
  { id: 'cloud', label: 'Cloud & Deploy', icon: Cloud },
  { id: 'ai', label: 'AI Orchestration', icon: Cpu },
  { id: 'secrets', label: 'Workspace Secrets', icon: Key },
  { id: 'danger', label: 'Danger Zone', icon: AlertTriangle },
];

const USER_TABS: Array<{ id: UserTabKey; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: 'account', label: 'Account', icon: User },
  { id: 'security', label: 'Security', icon: Shield },
  { id: 'privacy', label: 'Privacy & Data', icon: Lock },
  { id: 'billing', label: 'Usage', icon: Activity },
  { id: 'sessions', label: 'Devices & Sessions', icon: Laptop },
];

class Pixel {
  width: number;
  height: number;
  ctx: CanvasRenderingContext2D;
  x: number;
  y: number;
  color: string;
  speed: number;
  size: number;
  sizeStep: number;
  minSize: number;
  maxSizeInteger: number;
  maxSize: number;
  delay: number;
  counter: number;
  counterStep: number;
  isIdle: boolean;
  isReverse: boolean;
  isShimmer: boolean;

  constructor(canvas: HTMLCanvasElement, context: CanvasRenderingContext2D, x: number, y: number, color: string, speed: number, delay: number) {
    const dpr = window.devicePixelRatio || 1;
    this.width = canvas.width / dpr;
    this.height = canvas.height / dpr;
    this.ctx = context;
    this.x = x;
    this.y = y;
    this.color = color;
    this.speed = (Math.random() * 0.8 + 0.1) * speed;
    this.size = 0;
    this.sizeStep = Math.random() * 0.4;
    this.minSize = 0.5;
    this.maxSizeInteger = 2;
    this.maxSize = Math.random() * (this.maxSizeInteger - this.minSize) + this.minSize;
    this.delay = delay;
    this.counter = 0;
    this.counterStep = Math.random() * 4 + (this.width + this.height) * 0.01;
    this.isIdle = false;
    this.isReverse = false;
    this.isShimmer = false;
  }

  draw() {
    const offset = this.maxSizeInteger * 0.5 - this.size * 0.5;
    this.ctx.fillStyle = this.color;
    this.ctx.fillRect(this.x + offset, this.y + offset, this.size, this.size);
  }

  appear() {
    this.isIdle = false;
    if (this.counter <= this.delay) {
      this.counter += this.counterStep;
      return;
    }
    if (this.size >= this.maxSize) this.isShimmer = true;
    if (this.isShimmer) this.shimmer();
    else this.size += this.sizeStep;
    this.draw();
  }

  disappear() {
    this.isShimmer = false;
    this.counter = 0;
    if (this.size <= 0) {
      this.isIdle = true;
      return;
    }
    this.size -= 0.1;
    this.draw();
  }

  shimmer() {
    if (this.size >= this.maxSize) this.isReverse = true;
    else if (this.size <= this.minSize) this.isReverse = false;
    if (this.isReverse) this.size -= this.speed;
    else this.size += this.speed;
  }
}

interface PixelButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: 'default' | 'outline' | 'danger';
  className?: string;
  ariaLabel?: string;
}

function PixelButton({ children, onClick, disabled = false, variant = 'default', className = '', ariaLabel }: PixelButtonProps) {
  const containerRef = useRef<HTMLButtonElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const pixelsRef = useRef<Pixel[]>([]);
  const animationRef = useRef<number | null>(null);

  const colors = variant === 'danger'
    ? '#ffffff,#fca5a5,#b91c1c'
    : variant === 'outline'
      ? '#ffffff,#d4d4d8,#a1a1aa'
      : '#000000,#3f3f46,#71717a';

  const initPixels = useCallback(() => {
    if (!containerRef.current || !canvasRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;

    const dpr = window.devicePixelRatio || 1;
    const canvas = canvasRef.current;
    canvas.width = Math.floor(rect.width * dpr);
    canvas.height = Math.floor(rect.height * dpr);

    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);

    const colorsArray = colors.split(',');
    const pxs: Pixel[] = [];
    for (let x = 0; x < rect.width; x += 5) {
      for (let y = 0; y < rect.height; y += 5) {
        const color = colorsArray[Math.floor(Math.random() * colorsArray.length)] || '#ffffff';
        pxs.push(new Pixel(canvas, ctx, x, y, color, 0.06, 0));
      }
    }
    pixelsRef.current = pxs;
  }, [colors]);

  const triggerAnimation = useCallback((mode: 'appear' | 'disappear') => {
    if (animationRef.current !== null) {
      cancelAnimationFrame(animationRef.current);
      animationRef.current = null;
    }

    const tick = () => {
      const ctx = canvasRef.current?.getContext('2d');
      const canvas = canvasRef.current;
      if (!ctx || !canvas) {
        animationRef.current = null;
        return;
      }

      const dpr = window.devicePixelRatio || 1;
      ctx.clearRect(0, 0, canvas.width / dpr, canvas.height / dpr);

      let allIdle = true;
      pixelsRef.current.forEach((pixel) => {
        pixel[mode]();
        if (!pixel.isIdle) allIdle = false;
      });

      if (allIdle) {
        animationRef.current = null;
        return;
      }

      animationRef.current = requestAnimationFrame(tick);
    };

    animationRef.current = requestAnimationFrame(tick);
  }, []);

  useEffect(() => {
    initPixels();
    const observer = new ResizeObserver(() => initPixels());
    if (containerRef.current) observer.observe(containerRef.current);

    return () => {
      observer.disconnect();
      if (animationRef.current !== null) cancelAnimationFrame(animationRef.current);
    };
  }, [initPixels]);

  const base = 'relative overflow-hidden flex items-center justify-center rounded-md px-4 py-2 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-50';
  const styles = variant === 'danger'
    ? 'bg-[#EF4444] text-white hover:bg-red-500'
    : variant === 'outline'
      ? `border ${T.border} bg-transparent text-zinc-300 hover:border-zinc-500 hover:text-white`
      : `border ${T.border} bg-zinc-100 text-black hover:bg-white`;

  return (
    <button
      ref={containerRef}
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      className={`${base} ${styles} ${className}`}
      onMouseEnter={() => { if (!disabled) triggerAnimation('appear'); }}
      onMouseLeave={() => { if (!disabled) triggerAnimation('disappear'); }}
    >
      <canvas ref={canvasRef} className="pointer-events-none absolute inset-0 block" />
      <span className="relative z-10 flex items-center gap-2">{children}</span>
    </button>
  );
}

function statusPillClass(state: HealthState | 'unknown') {
  if (state === 'healthy') return 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30';
  if (state === 'degraded') return 'bg-amber-500/15 text-amber-300 border border-amber-500/30';
  if (state === 'down') return 'bg-rose-500/15 text-rose-300 border border-rose-500/30';
  return 'bg-zinc-700/20 text-zinc-300 border border-zinc-600/50';
}

function stateLabel(state: HealthState | 'unknown') {
  if (state === 'healthy') return 'Healthy';
  if (state === 'degraded') return 'Degraded';
  if (state === 'down') return 'Down';
  return 'Unknown';
}

function formatTimestamp(value: string | null): string {
  if (!value) return 'Never';
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return 'Unknown';
  return new Date(parsed).toLocaleString();
}

function SettingSection({
  title,
  description,
  badge,
  children,
}: {
  title: string;
  description?: string;
  badge?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className={`${T.surface} border ${T.border} mb-6 overflow-hidden rounded-xl`}>
      <div className={`flex items-start justify-between border-b ${T.border} p-6`}>
        <div>
          <h3 className="text-base font-semibold text-white">{title}</h3>
          {description ? <p className={`mt-1 text-sm ${T.muted}`}>{description}</p> : null}
        </div>
        {badge}
      </div>
      <div className="flex flex-col gap-6 p-6">{children}</div>
    </div>
  );
}

function SettingField({
  label,
  children,
  layout = 'horizontal',
}: {
  label: string;
  children: React.ReactNode;
  layout?: 'horizontal' | 'vertical';
}) {
  return (
    <div className={layout === 'horizontal' ? 'flex flex-col items-start justify-between gap-8 sm:flex-row' : 'flex flex-col gap-2'}>
      <label className={`shrink-0 text-sm font-medium ${T.text} ${layout === 'horizontal' ? 'pt-2 sm:w-1/3' : ''}`}>{label}</label>
      <div className={layout === 'horizontal' ? 'w-full flex-1' : 'w-full'}>{children}</div>
    </div>
  );
}

function EditableToggle({ active, onToggle }: { active: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className={`h-5 w-10 rounded-full border px-0.5 transition-all ${active ? 'border-white bg-white' : 'border-zinc-700 bg-zinc-950'}`}
      aria-pressed={active}
    >
      <span className={`block h-3.5 w-3.5 rounded-full transition-all ${active ? 'translate-x-5 bg-black' : 'translate-x-0 bg-zinc-500'}`} />
    </button>
  );
}

function ReadonlyTextInput({ value, dataField }: { value: string; dataField?: string }) {
  return (
    <input
      value={value}
      disabled
      data-field={dataField}
      className={`w-full rounded-md border ${T.border} ${T.bg} px-3 py-2.5 text-sm ${T.text} disabled:opacity-60`}
      onChange={() => undefined}
    />
  );
}

function ReadonlySelectInput({ value, dataField }: { value: string; dataField?: string }) {
  return (
    <div className="relative w-full">
      <select
        disabled
        data-field={dataField}
        className={`w-full appearance-none rounded-md border ${T.border} ${T.bg} pl-3 pr-8 py-2.5 text-sm ${T.text} disabled:opacity-60`}
      >
        <option>{value}</option>
      </select>
      <ChevronDown className={`pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 ${T.hint}`} />
    </div>
  );
}

function StatusBadge({ status, label }: { status: 'success' | 'idle'; label: string }) {
  const success = status === 'success';
  return (
    <div className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider ${success ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400' : 'border-zinc-500/20 bg-zinc-500/10 text-zinc-400'}`}>
      {success ? <CheckCircle2 className="h-3 w-3" /> : <Activity className="h-3 w-3" />}
      {label}
    </div>
  );
}

function EditableSecretInput({
  label,
  value,
  onChange,
  configured,
  placeholder,
  helper,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  configured: boolean;
  placeholder: string;
  helper?: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <div className="space-y-2">
      <label className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">{label}</label>
      <div className="relative">
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder={configured ? 'Configured. Enter new value to rotate.' : placeholder}
          className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2.5 pr-10 font-mono text-sm text-zinc-100 outline-none transition-colors focus:border-white/70"
        />
        <button
          type="button"
          onClick={() => setShow((current) => !current)}
          className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 transition-colors hover:text-zinc-200"
          aria-label={show ? 'Hide secret' : 'Show secret'}
        >
          {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
      {helper ? <p className="text-[11px] text-zinc-500">{helper}</p> : null}
    </div>
  );
}

type SessionUser = {
  id: string;
  githubId: number;
  login: string;
  email: string;
  name: string;
  avatarUrl: string;
};

const GITHUB_SECURITY_URL = 'https://github.com/settings/security';
const GITHUB_INSTALLATIONS_URL = 'https://github.com/settings/installations';
const GITHUB_APP_INSTALL_URL = `https://github.com/apps/${process.env.NEXT_PUBLIC_GITHUB_APP_SLUG || 'deplai-app'}/installations/new`;

function ExternalLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center rounded-md border border-[#2D3039] px-3 py-2 text-sm text-zinc-200 transition-colors hover:bg-white/5"
    >
      {children}
    </a>
  );
}

function SignedOutNotice() {
  return (
    <div className={`rounded-md border ${T.border} ${T.bg} p-4 text-sm ${T.muted}`}>
      You are not signed in, so there is nothing to show here yet.
    </div>
  );
}

function UserAccountTab({ user }: { user: SessionUser | null }) {
  return (
    <div className="animate-in fade-in duration-300">
      <div className="mb-8">
        <h2 className="text-2xl font-bold tracking-tight text-white">Account Profile</h2>
        <p className={`mt-1 text-sm ${T.muted}`}>Your identity comes from GitHub, which is the only sign-in method.</p>
      </div>

      {!user ? <SignedOutNotice /> : (
        <>
          <SettingSection title="Profile">
            <div className="flex items-center gap-6">
              {user.avatarUrl ? (
                <Image src={user.avatarUrl} alt={`${user.login} avatar`} width={80} height={80} className="h-20 w-20 shrink-0 rounded-full border border-[#2D3039]" />
              ) : (
                <div className="flex h-20 w-20 shrink-0 items-center justify-center rounded-full border border-[#2D3039] bg-[#1A1C23] text-2xl font-bold text-white" aria-hidden="true">
                  {(user.name || user.login || '?').slice(0, 2).toUpperCase()}
                </div>
              )}
              <div className="min-w-0">
                <p className="truncate text-lg font-semibold text-white">{user.name || user.login}</p>
                <p className={`truncate text-sm ${T.mono} ${T.muted}`}>@{user.login}</p>
              </div>
            </div>
            <SettingField label="Name"><ReadonlyTextInput value={user.name || '-'} /></SettingField>
            <SettingField label="GitHub username"><ReadonlyTextInput value={user.login} /></SettingField>
            <SettingField label="Email"><ReadonlyTextInput value={user.email || '-'} /></SettingField>
            <p className="text-[11px] text-zinc-500">To change your name, email or photo, update your GitHub profile; the next sign-in picks it up.</p>
          </SettingSection>

          <SettingSection title="GitHub access">
            <p className={`text-sm ${T.muted}`}>Repository access is granted through the DeplAI GitHub App. Install it on more repositories, or review what it can see, on GitHub.</p>
            <div className="flex flex-wrap gap-3">
              <ExternalLink href={`https://github.com/${encodeURIComponent(user.login)}`}>View GitHub profile</ExternalLink>
              <ExternalLink href={GITHUB_APP_INSTALL_URL}>Install the GitHub App</ExternalLink>
              <ExternalLink href={GITHUB_INSTALLATIONS_URL}>Manage installations</ExternalLink>
            </div>
          </SettingSection>
        </>
      )}
    </div>
  );
}

function UserSecurityTab() {
  return (
    <div className="animate-in fade-in duration-300">
      <div className="mb-8">
        <h2 className="text-2xl font-bold tracking-tight text-white">Security</h2>
        <p className={`mt-1 text-sm ${T.muted}`}>How sign-in is protected.</p>
      </div>

      <SettingSection title="Sign-in">
        <p className={`text-sm ${T.muted}`}>
          DeplAI does not have its own passwords, authenticator codes or passkeys. You sign in with GitHub, so your password, two-factor
          authentication and passkeys are managed in your GitHub security settings.
        </p>
        <div>
          <ExternalLink href={GITHUB_SECURITY_URL}>Open GitHub security settings</ExternalLink>
        </div>
      </SettingSection>
    </div>
  );
}

function UserPrivacyTab({ onExport, exporting }: { onExport: () => void; exporting: boolean }) {
  return (
    <div className="animate-in fade-in duration-300">
      <div className="mb-8">
        <h2 className="text-2xl font-bold tracking-tight text-white">Privacy & Data</h2>
        <p className={`mt-1 text-sm ${T.muted}`}>Get a copy of what DeplAI stores about you.</p>
      </div>

      <SettingSection title="Export my data">
        <p className={`text-sm ${T.muted}`}>
          Downloads a JSON file with your account record, saved settings (API keys and secrets are never included), projects, connected GitHub installations and
          repositories, and your chat history.
        </p>
        <div>
          <PixelButton variant="default" onClick={onExport} disabled={exporting}>{exporting ? 'Preparing export...' : 'Export My Data'}</PixelButton>
        </div>
      </SettingSection>

      <SettingSection title="Deletion">
        <p className={`text-sm ${T.muted}`}>
          Self-service account deletion is not available. Remove a project from the dashboard to stop tracking it, or ask the workspace administrator to delete your
          account and any cloned repositories on the server.
        </p>
      </SettingSection>
    </div>
  );
}

function UserUsageTab({ projectCount, installationCount }: { projectCount: number; installationCount: number }) {
  return (
    <div className="animate-in fade-in duration-300">
      <div className="mb-8">
        <h2 className="text-2xl font-bold tracking-tight text-white">Usage</h2>
        <p className={`mt-1 text-sm ${T.muted}`}>What is currently set up in your workspace.</p>
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
        {[
          { label: 'Projects', value: String(projectCount) },
          { label: 'GitHub installations', value: String(installationCount) },
        ].map((card) => (
          <div key={card.label} className={`rounded-xl border ${T.border} ${T.surface} p-6`}>
            <p className="mb-2 text-xs font-bold uppercase tracking-widest text-zinc-400">{card.label}</p>
            <p className="text-3xl font-bold text-white">{card.value}</p>
          </div>
        ))}
      </div>
      <p className={`text-sm ${T.muted}`}>Token usage and cost are not metered, and there is no billing system, so only live counts are shown.</p>
    </div>
  );
}

function UserSessionsTab({ user, onSignOut, signingOut }: { user: SessionUser | null; onSignOut: () => void; signingOut: boolean }) {
  return (
    <div className="animate-in fade-in duration-300">
      <div className="mb-8">
        <h2 className="text-2xl font-bold tracking-tight text-white">Devices & Sessions</h2>
        <p className={`mt-1 text-sm ${T.muted}`}>Your current sign-in.</p>
      </div>

      {!user ? <SignedOutNotice /> : (
        <SettingSection title="This device">
          <div className={`flex flex-col items-start justify-between gap-4 rounded-md border ${T.border} ${T.bg} p-4 sm:flex-row sm:items-center`}>
            <div className="flex items-center gap-3">
              <Laptop className="h-5 w-5 text-emerald-400" aria-hidden="true" />
              <div className="text-sm">
                <p className="font-medium text-white">Signed in as @{user.login}</p>
                <p className="text-xs text-zinc-500">Via GitHub. The session lasts up to 7 days or until you sign out.</p>
              </div>
            </div>
            <PixelButton variant="outline" onClick={onSignOut} disabled={signingOut}>{signingOut ? 'Signing out...' : 'Sign out'}</PixelButton>
          </div>
          <p className="text-[11px] text-zinc-500">
            A list of other devices and &quot;sign out everywhere&quot; are not available: sessions live in an encrypted cookie on each device, not on the server.
          </p>
        </SettingSection>
      )}
    </div>
  );
}

export default function SettingsApp() {
  const { setProvider, setModel, setApiKey } = useLLM();

  const [activeContext, setActiveContext] = useState<ContextKey>('workspace');
  const [activeTab, setActiveTab] = useState<TabKey>('integrations');

  const [settings, setSettings] = useState<PublicSettings>(DEFAULT_SETTINGS);
  const [serverConfig, setServerConfig] = useState<ServerConfig>(DEFAULT_SERVER_CONFIG);
  const [live, setLive] = useState<LiveMetrics>(DEFAULT_LIVE);
  const [secretDrafts, setSecretDrafts] = useState<SecretDrafts>(DEFAULT_SECRET_DRAFTS);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [liveRefreshing, setLiveRefreshing] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);
  const [busy, setBusy] = useState<'' | 'github' | 'aws' | 'export' | 'signout'>('');

  const [cleanupPhrase, setCleanupPhrase] = useState('');
  const [cleanupRunning, setCleanupRunning] = useState(false);
  const [cleanupResult, setCleanupResult] = useState('');

  const allTabs = useMemo(() => [...WORKSPACE_TABS, ...USER_TABS], []);

  const providerConfig = useMemo(
    () => LLM_PROVIDERS.find((provider) => provider.id === settings.ai.provider),
    [settings.ai.provider]
  );

  const providerModels = useMemo(() => {
    const known = PROVIDER_MODELS[settings.ai.provider] || [];
    return known.includes(settings.ai.model) ? known : [settings.ai.model, ...known];
  }, [settings.ai.model, settings.ai.provider]);

  const checksByName = useMemo(
    () => Object.fromEntries(live.checks.map((check) => [check.name, check])),
    [live.checks]
  );

  const activeLabel = useMemo(
    () => allTabs.find((tab) => tab.id === activeTab)?.label ?? '',
    [activeTab, allTabs]
  );

  const applySettingsPayload = useCallback((payload: SettingsResponse) => {
    if (payload.settings) {
      setSettings(payload.settings);
      setProvider(payload.settings.ai.provider);
      setModel(payload.settings.ai.provider, payload.settings.ai.model);
    }
    if (payload.serverConfig) setServerConfig(payload.serverConfig);
    setUpdatedAt(payload.updatedAt ?? null);
  }, [setModel, setProvider]);

  const loadSettings = useCallback(async () => {
    const response = await fetch('/api/settings', { cache: 'no-store' });
    const payload = await response.json() as SettingsResponse;
    if (!response.ok) throw new Error(payload.error || 'Failed to load settings');
    applySettingsPayload(payload);
  }, [applySettingsPayload]);

  const loadSession = useCallback(async () => {
    try {
      const response = await fetch('/api/auth/session', { cache: 'no-store' });
      const payload = await response.json() as { isLoggedIn?: boolean; user?: SessionUser };
      setSessionUser(payload.isLoggedIn && payload.user ? payload.user : null);
    } catch {
      setSessionUser(null);
    }
  }, []);

  const loadLiveMetrics = useCallback(async () => {
    setLiveRefreshing(true);
    try {
      const [projectsRes, installationsRes, healthRes] = await Promise.all([
        fetch('/api/projects', { cache: 'no-store' }),
        fetch('/api/installations', { cache: 'no-store' }),
        fetch('/api/pipeline/health', { cache: 'no-store' }),
      ]);

      const projectsPayload = projectsRes.ok ? await projectsRes.json() as ProjectsResponse : { projects: [] };
      const installationsPayload = installationsRes.ok ? await installationsRes.json() as InstallationsResponse : { installations: [] };
      const healthPayload = healthRes.ok ? await healthRes.json() as HealthResponse : { overall: 'unknown', checks: [] };

      const normalizedChecks = Array.isArray(healthPayload.checks)
        ? healthPayload.checks
            .filter((check) => check?.name)
            .map((check) => ({
              name: String(check.name),
              state: check.state === 'healthy' || check.state === 'degraded' || check.state === 'down' ? check.state : 'degraded',
              detail: String(check.detail || ''),
            }))
        : [];

      setLive({
        projectCount: Array.isArray(projectsPayload.projects) ? projectsPayload.projects.length : 0,
        installationCount: Array.isArray(installationsPayload.installations) ? installationsPayload.installations.length : 0,
        healthOverall: healthPayload.overall === 'healthy' || healthPayload.overall === 'degraded' || healthPayload.overall === 'down' ? healthPayload.overall : 'unknown',
        checks: normalizedChecks,
        lastRefreshedAt: new Date().toISOString(),
      });
    } catch {
      setLive((current) => ({ ...current, lastRefreshedAt: new Date().toISOString() }));
    } finally {
      setLiveRefreshing(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    const bootstrap = async () => {
      setLoading(true);
      setError('');
      try {
        await Promise.all([loadSettings(), loadLiveMetrics(), loadSession()]);
      } catch (err) {
        if (!cancelled) {
          const message = err instanceof Error ? err.message : 'Failed to load settings';
          setError(message);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    void bootstrap();

    const interval = window.setInterval(() => {
      void loadLiveMetrics();
    }, 8000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [loadLiveMetrics, loadSession, loadSettings]);

  const updateSecretDraft = useCallback((key: keyof SecretDrafts, value: string) => {
    setSecretDrafts((current) => ({ ...current, [key]: value }));
  }, []);

  const handleTestGithub = useCallback(async () => {
    setBusy('github');
    setNotice('');
    setError('');
    try {
      const response = await fetch('/api/settings/test-github', { method: 'POST' });
      const result = await response.json() as {
        ok?: boolean;
        error?: string;
        app?: { name: string; slug: string; id: number; permissions: string[]; events: string[] };
      };
      if (result.ok && result.app) {
        const { name, slug, id, permissions, events } = result.app;
        setNotice(
          `Connected to GitHub App "${name}" (${slug}, id ${id}) with ${permissions.length} permission(s); subscribed events: ${events.join(', ') || 'none'}.`
        );
      } else {
        setError(result.error || 'GitHub App check failed.');
      }
    } catch {
      setError('Could not reach the server to test the GitHub App.');
    } finally {
      setBusy('');
    }
  }, []);

  const handleValidateAws = useCallback(async () => {
    setBusy('aws');
    setNotice('');
    setError('');
    try {
      const response = await fetch('/api/settings/validate-aws', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          accessKeyId: secretDrafts.awsAccessKeyId,
          secretAccessKey: secretDrafts.awsSecretAccessKey,
          region: settings.cloud.defaultRegion,
        }),
      });
      const result = await response.json() as { valid?: boolean; account?: string | null; arn?: string | null; error?: string | null };
      if (result.valid) {
        setNotice(`AWS credentials are valid (account ${result.account ?? 'unknown'}${result.arn ? `, ${result.arn}` : ''}).`);
      } else {
        setError(result.error || 'AWS credentials could not be validated.');
      }
    } catch {
      setError('Could not reach the server to validate AWS credentials.');
    } finally {
      setBusy('');
    }
  }, [secretDrafts.awsAccessKeyId, secretDrafts.awsSecretAccessKey, settings.cloud.defaultRegion]);

  const handleExport = useCallback(async () => {
    setBusy('export');
    setNotice('');
    setError('');
    try {
      const response = await fetch('/api/settings/export', { cache: 'no-store' });
      if (!response.ok) throw new Error('Export failed');
      const blob = await response.blob();
      const disposition = response.headers.get('Content-Disposition') || '';
      const filename = /filename="([^"]+)"/.exec(disposition)?.[1] || 'deplai-export.json';
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setNotice(`Exported your data to ${filename}.`);
    } catch {
      setError('Could not export your data.');
    } finally {
      setBusy('');
    }
  }, []);

  const handleSignOut = useCallback(async () => {
    setBusy('signout');
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } finally {
      window.location.assign('/');
    }
  }, []);

  const handleSave = useCallback(async () => {
    setSaving(true);
    setNotice('');
    setError('');

    try {
      const payload = {
        settings: {
          integrations: {
            githubAppActive: settings.integrations.githubAppActive,
            githubAppId: settings.integrations.githubAppId,
            githubPrivateKey: secretDrafts.githubPrivateKey.trim() || undefined,
            webhookSecret: secretDrafts.webhookSecret.trim() || undefined,
          },
          cloud: {
            defaultRegion: settings.cloud.defaultRegion,
            monthlyBudgetUsd: settings.cloud.monthlyBudgetUsd,
            budgetOverride: settings.cloud.budgetOverride,
            awsAccessKeyId: secretDrafts.awsAccessKeyId.trim() || undefined,
            awsSecretAccessKey: secretDrafts.awsSecretAccessKey.trim() || undefined,
          },
          ai: {
            provider: settings.ai.provider,
            model: settings.ai.model,
            maxExecutionCycles: settings.ai.maxExecutionCycles,
            autoApproveLow: settings.ai.autoApproveLow,
            apiKey: secretDrafts.aiApiKey.trim() || undefined,
          },
          workspace: {
            serviceKey: secretDrafts.serviceKey.trim() || undefined,
            sessionSecret: secretDrafts.sessionSecret.trim() || undefined,
            wsTokenSecret: secretDrafts.wsTokenSecret.trim() || undefined,
          },
        },
      };

      const response = await fetch('/api/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const result = await response.json() as SettingsResponse;
      if (!response.ok) throw new Error(result.error || 'Failed to save settings');

      applySettingsPayload(result);
      setSecretDrafts(DEFAULT_SECRET_DRAFTS);

      setProvider(settings.ai.provider);
      setModel(settings.ai.provider, settings.ai.model);
      if (payload.settings.ai.apiKey) {
        setApiKey(settings.ai.provider, payload.settings.ai.apiKey);
      }

      setNotice('Settings saved successfully.');
      void loadLiveMetrics();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save settings';
      setError(message);
    } finally {
      setSaving(false);
    }
  }, [
    applySettingsPayload,
    loadLiveMetrics,
    secretDrafts.aiApiKey,
    secretDrafts.awsAccessKeyId,
    secretDrafts.awsSecretAccessKey,
    secretDrafts.githubPrivateKey,
    secretDrafts.serviceKey,
    secretDrafts.sessionSecret,
    secretDrafts.webhookSecret,
    secretDrafts.wsTokenSecret,
    setApiKey,
    setModel,
    setProvider,
    settings.ai.autoApproveLow,
    settings.ai.maxExecutionCycles,
    settings.ai.model,
    settings.ai.provider,
    settings.cloud.budgetOverride,
    settings.cloud.defaultRegion,
    settings.cloud.monthlyBudgetUsd,
    settings.integrations.githubAppActive,
    settings.integrations.githubAppId,
  ]);

  const handleCleanup = useCallback(async () => {
    setCleanupResult('');
    setError('');
    setCleanupRunning(true);
    try {
      const response = await fetch('/api/settings/cleanup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirmation: cleanupPhrase }),
      });

      const payload = await response.json() as { error?: string; message?: string };
      if (!response.ok) throw new Error(payload.error || 'Failed to execute cleanup');

      setCleanupResult(payload.message || 'Cleanup completed.');
      setCleanupPhrase('');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to execute cleanup';
      setCleanupResult(message);
    } finally {
      setCleanupRunning(false);
    }
  }, [cleanupPhrase]);

  const openWorkspaceTab = (tab: WorkspaceTabKey) => {
    setActiveContext('workspace');
    setActiveTab(tab);
  };

  const openUserTab = (tab: UserTabKey) => {
    setActiveContext('user');
    setActiveTab(tab);
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center py-20 text-zinc-400">
        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
        Loading settings...
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-16">
      <div className="rounded-xl border border-zinc-800 bg-black/40 p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-xl font-semibold text-white">Settings</h2>
            <p className="mt-1 text-sm text-zinc-400">Updated UI synced from settings-ui.txt with live backend wiring.</p>
            <p className="mt-1 text-[11px] text-zinc-500">Last saved: {formatTimestamp(updatedAt)}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void loadLiveMetrics()}
              className="inline-flex items-center gap-2 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs font-medium text-zinc-200 transition-colors hover:bg-zinc-800"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${liveRefreshing ? 'animate-spin' : ''}`} />
              Refresh Live Status
            </button>
            <button
              type="button"
              onClick={() => void handleSave()}
              disabled={saving}
              className="inline-flex items-center gap-2 rounded-md bg-white px-3.5 py-2 text-xs font-semibold text-black transition-colors hover:bg-zinc-300 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
              Save Changes
            </button>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-zinc-400">
          <span className="rounded border border-zinc-700 px-2 py-0.5">{activeContext === 'workspace' ? 'Workspace' : 'Your Account'}</span>
          <span className="text-zinc-600">/</span>
          <span className="font-medium text-zinc-200">{activeLabel}</span>
        </div>
      </div>

      {error ? <div className="rounded-md border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-300">{error}</div> : null}
      {notice ? <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-sm text-emerald-300">{notice}</div> : null}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <aside className="space-y-6 lg:col-span-3">
          <div>
            <h4 className="mb-3 px-1 text-[10px] font-bold uppercase tracking-widest text-zinc-500">Workspace</h4>
            <div className="space-y-1">
              {WORKSPACE_TABS.map((tab) => {
                const Icon = tab.icon;
                const active = activeContext === 'workspace' && activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => openWorkspaceTab(tab.id)}
                    className={`flex w-full items-center justify-between rounded-md border px-3 py-2.5 text-left text-sm transition-colors ${active ? 'border-zinc-700 bg-zinc-900 text-white' : 'border-transparent text-zinc-400 hover:bg-zinc-900/60 hover:text-zinc-100'}`}
                  >
                    <span className="flex items-center gap-2.5"><Icon className="h-4 w-4" />{tab.label}</span>
                    {active ? <span className="h-4 w-1 rounded-full bg-[#4F6EF7]" /> : null}
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <h4 className="mb-3 px-1 text-[10px] font-bold uppercase tracking-widest text-zinc-500">Your Account</h4>
            <div className="space-y-1">
              {USER_TABS.map((tab) => {
                const Icon = tab.icon;
                const active = activeContext === 'user' && activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => openUserTab(tab.id)}
                    className={`flex w-full items-center justify-between rounded-md border px-3 py-2.5 text-left text-sm transition-colors ${active ? 'border-zinc-700 bg-zinc-900 text-white' : 'border-transparent text-zinc-400 hover:bg-zinc-900/60 hover:text-zinc-100'}`}
                  >
                    <span className="flex items-center gap-2.5"><Icon className="h-4 w-4" />{tab.label}</span>
                    {active ? <span className="h-4 w-1 rounded-full bg-white" /> : null}
                  </button>
                );
              })}
            </div>
          </div>
        </aside>

        <section className="lg:col-span-9">
          {activeContext === 'workspace' && activeTab === 'integrations' ? (
            <div className="animate-in fade-in duration-300">
              <div className="mb-8">
                <h2 className="text-2xl font-bold tracking-tight text-white">Integrations</h2>
                <p className={`mt-1 text-sm ${T.muted}`}>Manage source control and webhook integrations for the workspace.</p>
              </div>

              <SettingSection title="GitHub App" badge={<StatusBadge status="success" label="Connected" />}>
                <div className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-950 p-3">
                  <p className="text-sm text-zinc-300">GitHub App Active</p>
                  <EditableToggle
                    active={settings.integrations.githubAppActive}
                    onToggle={() => setSettings((current) => ({
                      ...current,
                      integrations: {
                        ...current.integrations,
                        githubAppActive: !current.integrations.githubAppActive,
                      },
                    }))}
                  />
                </div>

                <SettingField label="App ID">
                  <input
                    value={settings.integrations.githubAppId}
                    onChange={(event) => setSettings((current) => ({
                      ...current,
                      integrations: {
                        ...current.integrations,
                        githubAppId: event.target.value,
                      },
                    }))}
                    className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2.5 font-mono text-sm text-zinc-100 outline-none transition-colors focus:border-white/70"
                    placeholder="app_123456"
                  />
                </SettingField>

                <EditableSecretInput
                  label="Private Key"
                  value={secretDrafts.githubPrivateKey}
                  onChange={(value) => updateSecretDraft('githubPrivateKey', value)}
                  configured={settings.integrations.hasGithubPrivateKey || serverConfig.githubAppConfigured}
                  placeholder="-----BEGIN PRIVATE KEY-----"
                />

                <EditableSecretInput
                  label="Webhook Secret"
                  value={secretDrafts.webhookSecret}
                  onChange={(value) => updateSecretDraft('webhookSecret', value)}
                  configured={settings.integrations.hasWebhookSecret || serverConfig.githubWebhookConfigured}
                  placeholder="whsec_..."
                />

                <div className={`rounded-md border ${T.border} ${T.bg} p-4`}>
                  <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                    <div>
                      <p className={`mb-1 text-[10px] font-bold uppercase ${T.hint}`}>Webhook Health</p>
                      <span className={`rounded px-2 py-0.5 text-[11px] ${statusPillClass(checksByName.gitops_deploy?.state || 'unknown')}`}>{stateLabel(checksByName.gitops_deploy?.state || 'unknown')}</span>
                    </div>
                    <div>
                      <p className={`mb-1 text-[10px] font-bold uppercase ${T.hint}`}>Installations</p>
                      <p className={`text-sm ${T.mono}`}>{live.installationCount}</p>
                    </div>
                    <div>
                      <p className={`mb-1 text-[10px] font-bold uppercase ${T.hint}`}>App Env</p>
                      <p className={`text-sm ${T.mono}`}>{serverConfig.githubAppConfigured ? 'Configured' : 'Missing'}</p>
                    </div>
                    <div>
                      <p className={`mb-1 text-[10px] font-bold uppercase ${T.hint}`}>Webhook Env</p>
                      <p className={`text-sm ${T.mono}`}>{serverConfig.githubWebhookConfigured ? 'Configured' : 'Missing'}</p>
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <PixelButton variant="default" onClick={() => void handleTestGithub()} disabled={busy === 'github'}>
                    {busy === 'github' ? 'Testing...' : 'Test Connection'}
                  </PixelButton>
                  <PixelButton variant="outline" onClick={() => window.open(GITHUB_APP_INSTALL_URL, '_blank', 'noopener,noreferrer')}>
                    Install / Re-authorize App
                  </PixelButton>
                </div>
              </SettingSection>

              <SettingSection title="Coming Soon Connectors">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  {['Jira', 'Slack', 'PagerDuty'].map((tool) => (
                    <div key={tool} className={`flex flex-col items-center justify-center gap-3 rounded-lg border ${T.border} bg-[#0A0B0F]/50 p-5 opacity-60`}>
                      <div className="flex h-10 w-10 items-center justify-center rounded-full border border-[#1E2028] bg-[#111318]"><Network className="h-5 w-5 text-zinc-500" /></div>
                      <span className="text-sm font-medium text-zinc-400">{tool}</span>
                      <span className="rounded bg-zinc-800/50 px-2 py-0.5 text-[9px] font-bold uppercase tracking-widest text-zinc-500">Coming Soon</span>
                    </div>
                  ))}
                </div>
              </SettingSection>
            </div>
          ) : null}

          {activeContext === 'workspace' && activeTab === 'cloud' ? (
            <div className="animate-in fade-in duration-300">
              <div className="mb-8">
                <h2 className="text-2xl font-bold tracking-tight text-white">Cloud & Deploy</h2>
                <p className={`mt-1 text-sm ${T.muted}`}>Configure target environments and financial guardrails.</p>
              </div>

              <SettingSection title="Provider Credentials">
                <SettingField label="Provider"><ReadonlySelectInput value="AWS" dataField="cloudProvider" /></SettingField>
                <EditableSecretInput
                  label="Access Key ID"
                  value={secretDrafts.awsAccessKeyId}
                  onChange={(value) => updateSecretDraft('awsAccessKeyId', value)}
                  configured={settings.cloud.hasAwsAccessKeyId || serverConfig.awsRuntimeConfigured}
                  placeholder="AKIA..."
                />
                <EditableSecretInput
                  label="Secret Access Key"
                  value={secretDrafts.awsSecretAccessKey}
                  onChange={(value) => updateSecretDraft('awsSecretAccessKey', value)}
                  configured={settings.cloud.hasAwsSecretAccessKey || serverConfig.awsRuntimeConfigured}
                  placeholder="wJalrXU..."
                />
                <SettingField label="Default Region">
                  <select
                    value={settings.cloud.defaultRegion}
                    onChange={(event) => setSettings((current) => ({
                      ...current,
                      cloud: {
                        ...current.cloud,
                        defaultRegion: event.target.value,
                      },
                    }))}
                    className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-sm text-zinc-100 outline-none transition-colors focus:border-white/70"
                  >
                    {REGION_OPTIONS.map((region) => <option key={region} value={region}>{region}</option>)}
                  </select>
                </SettingField>

                <div className="flex flex-wrap items-center gap-3">
                  <PixelButton variant="default" onClick={() => void handleValidateAws()} disabled={busy === 'aws'}>
                    {busy === 'aws' ? 'Validating...' : 'Validate Credentials'}
                  </PixelButton>
                </div>
              </SettingSection>

              <SettingSection title="Budget Guardrails">
                <SettingField label="Monthly Cap">
                  <div className="relative">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-sm text-zinc-500">$</span>
                    <input
                      type="number"
                      min={1}
                      value={settings.cloud.monthlyBudgetUsd}
                      onChange={(event) => setSettings((current) => ({
                        ...current,
                        cloud: {
                          ...current.cloud,
                          monthlyBudgetUsd: Math.max(1, Number(event.target.value || 1)),
                        },
                      }))}
                      className="w-full rounded-md border border-zinc-800 bg-zinc-950 py-2.5 pl-7 pr-3 font-mono text-sm text-zinc-100 outline-none transition-colors focus:border-white/70"
                    />
                  </div>
                </SettingField>

                <SettingField label="Budget Override">
                  <EditableToggle
                    active={settings.cloud.budgetOverride}
                    onToggle={() => setSettings((current) => ({
                      ...current,
                      cloud: {
                        ...current.cloud,
                        budgetOverride: !current.cloud.budgetOverride,
                      },
                    }))}
                  />
                </SettingField>

                <div className={`rounded-md border ${T.border} bg-zinc-950 px-3 py-2`}>
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-300">Runtime deploy health</span>
                    <span className={`rounded px-2 py-1 text-xs ${statusPillClass(checksByName.runtime_deploy?.state || 'unknown')}`}>
                      {stateLabel(checksByName.runtime_deploy?.state || 'unknown')}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-zinc-500">{checksByName.runtime_deploy?.detail || 'No health detail yet.'}</p>
                </div>
              </SettingSection>
            </div>
          ) : null}

          {activeContext === 'workspace' && activeTab === 'ai' ? (
            <div className="animate-in fade-in duration-300">
              <div className="mb-8">
                <h2 className="text-2xl font-bold tracking-tight text-white">AI Orchestration</h2>
                <p className={`mt-1 text-sm ${T.muted}`}>Manage model routing, API keys, and remediation limits.</p>
              </div>

              <SettingSection title="Provider & Model">
                <div className="grid grid-cols-1 gap-8 md:grid-cols-2">
                  <div className="space-y-4 md:border-r md:border-[#1E2028] md:pr-8">
                    <SettingField label="Primary Provider" layout="vertical">
                      <select
                        value={settings.ai.provider}
                        onChange={(event) => {
                          const provider = event.target.value as LLMProvider;
                          const nextModel = PROVIDER_MODELS[provider]?.[0] || settings.ai.model;
                          setSettings((current) => ({
                            ...current,
                            ai: {
                              ...current.ai,
                              provider,
                              model: nextModel,
                            },
                          }));
                        }}
                        className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-sm text-zinc-100 outline-none transition-colors focus:border-white/70"
                      >
                        {LLM_PROVIDERS.map((provider) => <option key={provider.id} value={provider.id}>{provider.label}</option>)}
                      </select>
                    </SettingField>

                    <EditableSecretInput
                      label={`${providerConfig?.label || 'Provider'} API Key`}
                      value={secretDrafts.aiApiKey}
                      onChange={(value) => updateSecretDraft('aiApiKey', value)}
                      configured={settings.ai.hasApiKey}
                      placeholder={providerConfig?.placeholder || 'Enter API key'}
                    />
                  </div>

                  <div className="space-y-4">
                    <SettingField label="Model" layout="vertical">
                      <select
                        value={settings.ai.model}
                        onChange={(event) => setSettings((current) => ({
                          ...current,
                          ai: {
                            ...current.ai,
                            model: event.target.value,
                          },
                        }))}
                        className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-sm text-zinc-100 outline-none transition-colors focus:border-white/70"
                      >
                        {providerModels.map((model) => <option key={model} value={model}>{model}</option>)}
                      </select>
                    </SettingField>

                    <SettingField label="Max Execution Cycles" layout="vertical">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] uppercase tracking-wider text-zinc-500">Limit</span>
                          <span className="rounded bg-zinc-700/30 px-1.5 py-0.5 font-mono text-xs text-zinc-200">{settings.ai.maxExecutionCycles}</span>
                        </div>
                        <input
                          type="range"
                          min={1}
                          max={5}
                          value={settings.ai.maxExecutionCycles}
                          onChange={(event) => setSettings((current) => ({
                            ...current,
                            ai: {
                              ...current.ai,
                              maxExecutionCycles: Number(event.target.value),
                            },
                          }))}
                          className="w-full cursor-pointer accent-white"
                        />
                      </div>
                    </SettingField>

                    <SettingField label="Auto-Approve Low" layout="vertical">
                      <EditableToggle
                        active={settings.ai.autoApproveLow}
                        onToggle={() => setSettings((current) => ({
                          ...current,
                          ai: {
                            ...current.ai,
                            autoApproveLow: !current.ai.autoApproveLow,
                          },
                        }))}
                      />
                    </SettingField>
                  </div>
                </div>

                <div className={`rounded-md border ${T.border} bg-zinc-950 px-3 py-2`}>
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-300">Remediation engine</span>
                    <span className={`rounded px-2 py-1 text-xs ${statusPillClass(checksByName.remediation?.state || 'unknown')}`}>{stateLabel(checksByName.remediation?.state || 'unknown')}</span>
                  </div>
                  <p className="mt-1 text-xs text-zinc-500">{checksByName.remediation?.detail || 'No health detail yet.'}</p>
                </div>
              </SettingSection>
            </div>
          ) : null}

          {activeContext === 'workspace' && activeTab === 'secrets' ? (
            <div className="animate-in fade-in duration-300">
              <div className="mb-8">
                <h2 className="text-2xl font-bold tracking-tight text-white">Workspace Secrets</h2>
                <p className={`mt-1 text-sm ${T.muted}`}>Internal platform credentials and symmetric keys. Encrypted at rest.</p>
              </div>

              <SettingSection title="Platform Secrets">
                <EditableSecretInput
                  label="DeplAI Service Key"
                  value={secretDrafts.serviceKey}
                  onChange={(value) => updateSecretDraft('serviceKey', value)}
                  configured={settings.workspace.hasServiceKey || serverConfig.serviceKeyConfigured}
                  placeholder="d3pl41_svckey_..."
                />

                <EditableSecretInput
                  label="Session Secret"
                  value={secretDrafts.sessionSecret}
                  onChange={(value) => updateSecretDraft('sessionSecret', value)}
                  configured={settings.workspace.hasSessionSecret || serverConfig.sessionSecretConfigured}
                  placeholder="session_secret..."
                />

                <EditableSecretInput
                  label="WebSocket Token Secret"
                  value={secretDrafts.wsTokenSecret}
                  onChange={(value) => updateSecretDraft('wsTokenSecret', value)}
                  configured={settings.workspace.hasWsTokenSecret}
                  placeholder="ws_token_secret..."
                />

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm">
                    <p className="text-zinc-300">Session secret in env</p>
                    <p className="mt-1 text-xs text-zinc-500">{serverConfig.sessionSecretConfigured ? 'Configured' : 'Missing'}</p>
                  </div>
                  <div className="rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm">
                    <p className="text-zinc-300">Service key in env</p>
                    <p className="mt-1 text-xs text-zinc-500">{serverConfig.serviceKeyConfigured ? 'Configured' : 'Missing'}</p>
                  </div>
                </div>
              </SettingSection>
            </div>
          ) : null}

          {activeContext === 'workspace' && activeTab === 'danger' ? (
            <div className="animate-in fade-in duration-300">
              <div className="mb-8 border-b border-rose-500/30 pb-4">
                <h2 className="text-2xl font-bold tracking-tight text-rose-500">Danger Zone</h2>
                <p className="mt-1 text-sm text-rose-400/80">Irreversible operations. Owner privileges required.</p>
              </div>

              <SettingSection title="Global Runtime Cleanup" description="This calls the real backend cleanup endpoint and can permanently remove runtime artifacts.">
                <div className="rounded-md border border-rose-500/30 bg-black/30 p-3 text-xs text-rose-100/90">
                  <p>Type DESTROY ALL to continue.</p>
                  <p className="mt-1">Agentic layer cleanup currently: <strong>{serverConfig.cleanupEnabled ? 'enabled' : 'disabled'}</strong></p>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <input
                    value={cleanupPhrase}
                    onChange={(event) => setCleanupPhrase(event.target.value)}
                    placeholder="DESTROY ALL"
                    className="w-64 rounded-md border border-rose-400/50 bg-black/20 px-3 py-2.5 font-mono text-sm text-rose-100 outline-none transition-colors focus:border-rose-300"
                  />
                  <PixelButton
                    variant="danger"
                    onClick={() => void handleCleanup()}
                    disabled={cleanupRunning || cleanupPhrase.trim().toUpperCase() !== 'DESTROY ALL'}
                  >
                    {cleanupRunning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Database className="h-3.5 w-3.5" />}
                    Execute Cleanup
                  </PixelButton>
                </div>

                {cleanupResult ? <div className="rounded-md border border-rose-500/40 bg-black/30 px-3 py-2 text-sm text-rose-100">{cleanupResult}</div> : null}
              </SettingSection>
            </div>
          ) : null}

          {activeContext === 'user' && activeTab === 'account' ? <UserAccountTab user={sessionUser} /> : null}
          {activeContext === 'user' && activeTab === 'security' ? <UserSecurityTab /> : null}
          {activeContext === 'user' && activeTab === 'privacy' ? <UserPrivacyTab onExport={() => void handleExport()} exporting={busy === 'export'} /> : null}
          {activeContext === 'user' && activeTab === 'billing' ? <UserUsageTab projectCount={live.projectCount} installationCount={live.installationCount} /> : null}
          {activeContext === 'user' && activeTab === 'sessions' ? <UserSessionsTab user={sessionUser} onSignOut={() => void handleSignOut()} signingOut={busy === 'signout'} /> : null}
        </section>
      </div>

      <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-4">
        <h4 className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
          <CheckCircle2 className="h-4 w-4" />
          Live Service Checks
        </h4>
        {live.checks.length === 0 ? (
          <p className="text-sm text-zinc-500">No health checks returned yet.</p>
        ) : (
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {live.checks.map((check) => (
              <div key={check.name} className="rounded-md border border-zinc-800 bg-black/40 px-3 py-2">
                <div className="flex items-center justify-between gap-3">
                  <span className="truncate text-sm text-zinc-200">{check.name}</span>
                  <span className={`shrink-0 rounded px-2 py-0.5 text-[11px] ${statusPillClass(check.state)}`}>
                    {stateLabel(check.state)}
                  </span>
                </div>
                <p className="mt-1 text-xs text-zinc-500">{check.detail || 'No detail provided.'}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="text-[11px] text-zinc-500">
        Secret values are write-only in the UI. Existing secrets are never returned in API responses.
      </div>
    </div>
  );
}
