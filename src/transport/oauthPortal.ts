/**
 * Universal Sign-In Portal, 1-Tap Google Identity Services (GIS) OAuth2 Engine,
 * Live UserInfo Auto-Fetch & Custom Domain MX Auto-Discovery (`ATME/1.0`)
 *
 * Supports:
 *   1. Official Google Identity Services (`accounts.google.com/gsi/client`) Token Client
 *      + Centered `accounts.google.com/o/oauth2/v2/auth` Popup fallback
 *   2. Automatic Google Profile Fetch (`https://www.googleapis.com/oauth2/v3/userinfo`
 *      and `https://gmail.googleapis.com/gmail/v1/users/me/profile`) so signing up with
 *      a Google email requires ZERO manual typing of email or display name
 *   3. Real Microsoft Entra / Outlook OAuth2 PKCE Popup
 *   4. DNS-over-HTTPS (DoH) MX Record Auto-Discovery (`https://dns.google/resolve?name=<domain>&type=MX`)
 *      so custom school/club/workspace domains hosted on Google automatically route to 1-Click Google OAuth
 */

import { EmailProviderType } from '../protocol/types';

export interface GoogleUserProfileInfo {
  email: string;
  name: string;
  givenName?: string;
  pictureUrl?: string;
  emailVerified?: boolean;
}

export interface OAuthSignInResult {
  accessToken: string;
  expiresInSeconds?: number;
  scope?: string;
  userProfile?: GoogleUserProfileInfo;
}

export interface DomainAutoDiscoveryResult {
  domain: string;
  detectedProvider: EmailProviderType;
  providerLabel: string;
  authMethod:
    | 'oauth2-google'
    | 'oauth2-microsoft'
    | 'proton-bridge'
    | 'jmap-imap-password';
  mxRecords: string[];
  imapHost: string;
  imapPort: number;
  smtpHost: string;
  smtpPort: number;
  jmapEndpoint?: string;
  explanation: string;
}

export const GOOGLE_OAUTH_SCOPES = [
  'openid',
  'email',
  'profile',
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/gmail.settings.basic',
].join(' ');

const GOOGLE_CLIENT_ID_STORAGE_KEY = 'atme_google_oauth_client_id';
const GOOGLE_TOKEN_SESSION_KEY = 'atme_google_oauth_session';

const PLACEHOLDER_CLIENT_IDS = new Set([
  '1234567890-abcdefg.apps.googleusercontent.com',
  '123456789-abc.apps.googleusercontent.com',
  'your-google-oauth-client-id.apps.googleusercontent.com',
]);

/**
 * Strips common copy-paste artifacts from a Google OAuth Client ID:
 * - `VITE_GOOGLE_CLIENT_ID=` prefix (if pasted into Cloudflare env value by mistake)
 * - Surrounding single/double quotes or backticks
 * - Accidental whitespace or newlines
 */
export function sanitizeGoogleClientId(raw: string): string {
  if (!raw) return '';
  let clean = raw.trim();
  if (/^VITE_GOOGLE_CLIENT_ID\s*=/i.test(clean)) {
    clean = clean.replace(/^VITE_GOOGLE_CLIENT_ID\s*=/i, '').trim();
  }
  clean = clean.replace(/^["'`]+|["'`]+$/g, '').trim();
  clean = clean.replace(/\s+/g, '');
  return clean;
}

export function validateGoogleClientId(raw: string): {
  valid: boolean;
  sanitized: string;
  reason?: string;
} {
  const sanitized = sanitizeGoogleClientId(raw);
  if (!sanitized) {
    return { valid: false, sanitized: '' };
  }
  if (PLACEHOLDER_CLIENT_IDS.has(sanitized.toLowerCase())) {
    return {
      valid: false,
      sanitized,
      reason:
        'That is the example placeholder Client ID. Replace it with your real Client ID from Google Cloud Console.',
    };
  }
  if (sanitized.startsWith('GOCSPX-')) {
    return {
      valid: false,
      sanitized,
      reason:
        'That starts with "GOCSPX-", which is a Google Client Secret. Please paste the Client ID (ends with .apps.googleusercontent.com).',
    };
  }
  if (!sanitized.endsWith('.apps.googleusercontent.com')) {
    return {
      valid: false,
      sanitized,
      reason:
        'A Google Web Client ID must end with ".apps.googleusercontent.com".',
    };
  }
  return { valid: true, sanitized };
}

export function getSavedGoogleClientId(): string {
  try {
    const fromEnv = sanitizeGoogleClientId(
      (import.meta.env.VITE_GOOGLE_CLIENT_ID as string) || ''
    );
    const fromStorage = sanitizeGoogleClientId(
      localStorage.getItem(GOOGLE_CLIENT_ID_STORAGE_KEY) || ''
    );
    return fromStorage || fromEnv;
  } catch {
    return sanitizeGoogleClientId(
      (import.meta.env.VITE_GOOGLE_CLIENT_ID as string) || ''
    );
  }
}

export function saveGoogleClientId(clientId: string): void {
  try {
    const clean = sanitizeGoogleClientId(clientId);
    if (clean) {
      localStorage.setItem(GOOGLE_CLIENT_ID_STORAGE_KEY, clean);
    } else {
      localStorage.removeItem(GOOGLE_CLIENT_ID_STORAGE_KEY);
    }
  } catch {
    // Ignore storage quota errors
  }
}

export function saveGoogleOAuthSession(session: {
  email: string;
  accessToken: string;
  expiresAtMs: number;
}): void {
  try {
    localStorage.setItem(GOOGLE_TOKEN_SESSION_KEY, JSON.stringify(session));
  } catch {
    // Ignore storage quota errors
  }
}

export function loadGoogleOAuthSession(): {
  email: string;
  accessToken: string;
  expiresAtMs: number;
} | null {
  try {
    const raw = localStorage.getItem(GOOGLE_TOKEN_SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as {
      email: string;
      accessToken: string;
      expiresAtMs: number;
    };
    if (!parsed.accessToken || Date.now() >= parsed.expiresAtMs) {
      localStorage.removeItem(GOOGLE_TOKEN_SESSION_KEY);
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Generates a cryptographic PKCE `code_verifier` and `code_challenge` (S256) in the browser
 */
export async function generatePkceChallengePair(): Promise<{
  codeVerifier: string;
  codeChallenge: string;
}> {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const codeVerifier = Array.from(randomBytes, (b) =>
    b.toString(16).padStart(2, '0')
  ).join('');

  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(codeVerifier)
  );
  const base64Url = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return {
    codeVerifier,
    codeChallenge: base64Url,
  };
}

/**
 * Fetches the authenticated user's Google email, display name, and profile photo
 * directly from Google's UserInfo & Gmail Profile endpoints using the OAuth2 access token.
 */
export async function fetchGoogleUserProfile(
  accessToken: string
): Promise<GoogleUserProfileInfo> {
  const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (res.ok) {
    const data = (await res.json()) as {
      email?: string;
      name?: string;
      given_name?: string;
      picture?: string;
      email_verified?: boolean;
    };

    if (data.email) {
      const fallbackName = data.email
        .split('@')[0]
        .split(/[._-]/)
        .filter(Boolean)
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(' ');

      return {
        email: data.email.toLowerCase(),
        name: data.given_name || data.name || fallbackName || 'User',
        givenName: data.given_name,
        pictureUrl: data.picture,
        emailVerified: data.email_verified,
      };
    }
  }

  // Fallback to Gmail v1 users.getProfile if userinfo scope wasn't returned
  const gmailRes = await fetch(
    'https://gmail.googleapis.com/gmail/v1/users/me/profile',
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  if (gmailRes.ok) {
    const gmailData = (await gmailRes.json()) as { emailAddress?: string };
    if (gmailData.emailAddress) {
      const email = gmailData.emailAddress.toLowerCase();
      const name =
        email
          .split('@')[0]
          .split(/[._-]/)
          .filter(Boolean)
          .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
          .join(' ') || 'User';
      return { email, name, emailVerified: true };
    }
  }

  throw new Error('Could not retrieve Google account email from access token.');
}

/**
 * Dynamically loads the official Google Identity Services (`gsi/client`) SDK if not already present.
 */
let gisScriptPromise: Promise<boolean> | null = null;
export function loadGoogleIdentityServicesScript(): Promise<boolean> {
  if (typeof window === 'undefined') return Promise.resolve(false);
  const w = window as unknown as {
    google?: { accounts?: { oauth2?: unknown } };
  };
  if (w.google?.accounts?.oauth2) {
    return Promise.resolve(true);
  }
  if (gisScriptPromise) return gisScriptPromise;

  gisScriptPromise = new Promise((resolve) => {
    const existing = document.querySelector(
      'script[src="https://accounts.google.com/gsi/client"]'
    );
    if (existing) {
      existing.addEventListener('load', () => resolve(true), { once: true });
      existing.addEventListener('error', () => resolve(false), { once: true });
      return;
    }

    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = () => resolve(true);
    script.onerror = () => resolve(false);
    document.head.appendChild(script);
  });

  return gisScriptPromise;
}

/**
 * Inspects an email address and queries DNS-over-HTTPS (`dns.google`) for live MX records
 * (with deterministic fallback heuristics when offline) to automatically detect how any
 * custom domain is hosted.
 */
export async function discoverCustomDomainEmailConfig(
  emailAddress: string
): Promise<DomainAutoDiscoveryResult> {
  const clean = emailAddress.trim().toLowerCase();
  const domain = clean.includes('@') ? clean.split('@')[1] : clean;

  // Well-known consumer domains
  if (domain === 'gmail.com' || domain === 'googlemail.com') {
    return {
      domain,
      detectedProvider: 'gmail',
      providerLabel: 'Google Gmail',
      authMethod: 'oauth2-google',
      mxRecords: ['alt1.gmail-smtp-in.l.google.com'],
      imapHost: 'imap.gmail.com',
      imapPort: 993,
      smtpHost: 'smtp.gmail.com',
      smtpPort: 465,
      explanation: 'Consumer Google account — uses 1-Click Google OAuth2 Sign-In.',
    };
  }

  if (
    domain === 'outlook.com' ||
    domain === 'hotmail.com' ||
    domain === 'live.com' ||
    domain === 'msn.com'
  ) {
    return {
      domain,
      detectedProvider: 'outlook',
      providerLabel: 'Microsoft Outlook',
      authMethod: 'oauth2-microsoft',
      mxRecords: ['outlook-com.olc.protection.outlook.com'],
      imapHost: 'outlook.office365.com',
      imapPort: 993,
      smtpHost: 'smtp.office365.com',
      smtpPort: 587,
      explanation:
        'Microsoft account — uses 1-Click Microsoft OAuth2 PKCE Popup.',
    };
  }

  if (
    domain === 'proton.me' ||
    domain === 'protonmail.com' ||
    domain === 'pm.me'
  ) {
    return {
      domain,
      detectedProvider: 'proton',
      providerLabel: 'Proton Mail',
      authMethod: 'proton-bridge',
      mxRecords: ['mail.protonmail.ch'],
      imapHost: '127.0.0.1',
      imapPort: 1143,
      smtpHost: '127.0.0.1',
      smtpPort: 1025,
      explanation:
        'Proton Mail account — natively compatible with @me OpenPGP E2EE & Proton Mail Bridge.',
    };
  }

  if (domain === 'yahoo.com' || domain === 'ymail.com') {
    return {
      domain,
      detectedProvider: 'yahoo',
      providerLabel: 'Yahoo Mail',
      authMethod: 'jmap-imap-password',
      mxRecords: ['mta5.am0.yahoodns.net'],
      imapHost: 'imap.mail.yahoo.com',
      imapPort: 993,
      smtpHost: 'smtp.mail.yahoo.com',
      smtpPort: 465,
      explanation:
        'Yahoo Mail — connects via IMAP IDLE + App Password with server-side X-ATME-Protocol header filtering.',
    };
  }

  // Try live DNS-over-HTTPS MX lookup for custom domains (e.g., @stripe.com, @acme.io)
  let mxRecords: string[] = [];
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`
    );
    if (res.ok) {
      const data = (await res.json()) as {
        Answer?: Array<{ data: string }>;
      };
      if (data.Answer) {
        mxRecords = data.Answer.map((a) => a.data.toLowerCase());
      }
    }
  } catch {
    // Offline or sandboxed: fall through to heuristic MX inspection
  }

  const joinedMx = mxRecords.join(' ');

  if (
    joinedMx.includes('google.com') ||
    joinedMx.includes('googlemail.com') ||
    domain.endsWith('.google')
  ) {
    return {
      domain,
      detectedProvider: 'gmail',
      providerLabel: `Google Workspace (${domain})`,
      authMethod: 'oauth2-google',
      mxRecords: mxRecords.length ? mxRecords : ['aspmx.l.google.com'],
      imapHost: 'imap.gmail.com',
      imapPort: 993,
      smtpHost: 'smtp.gmail.com',
      smtpPort: 465,
      explanation: `Custom domain "${domain}" is hosted on Google Workspace! Users can sign in with 1-Click Google OAuth2 using their @${domain} email.`,
    };
  }

  if (
    joinedMx.includes('outlook.com') ||
    joinedMx.includes('protection.outlook.com')
  ) {
    return {
      domain,
      detectedProvider: 'outlook',
      providerLabel: `Microsoft 365 Custom Domain (${domain})`,
      authMethod: 'oauth2-microsoft',
      mxRecords: mxRecords.length
        ? mxRecords
        : [`${domain.replace(/\./g, '-')}.mail.protection.outlook.com`],
      imapHost: 'outlook.office365.com',
      imapPort: 993,
      smtpHost: 'smtp.office365.com',
      smtpPort: 587,
      explanation: `Custom domain "${domain}" is hosted on Microsoft 365! Users can sign in with 1-Click Microsoft OAuth2 using their @${domain} address.`,
    };
  }

  if (joinedMx.includes('protonmail.ch')) {
    return {
      domain,
      detectedProvider: 'proton',
      providerLabel: `Proton Mail Custom Domain (${domain})`,
      authMethod: 'proton-bridge',
      mxRecords: mxRecords.length ? mxRecords : ['mail.protonmail.ch'],
      imapHost: '127.0.0.1',
      imapPort: 1143,
      smtpHost: '127.0.0.1',
      smtpPort: 1025,
      explanation: `Custom domain "${domain}" uses Proton Mail MX records! Natively supports OpenPGP E2EE and Proton Bridge.`,
    };
  }

  if (joinedMx.includes('messagingengine.com') || domain.includes('fastmail')) {
    return {
      domain,
      detectedProvider: 'custom-domain',
      providerLabel: `Fastmail JMAP Custom Domain (${domain})`,
      authMethod: 'jmap-imap-password',
      mxRecords: mxRecords.length
        ? mxRecords
        : ['in1-smtp.messagingengine.com'],
      imapHost: 'imap.fastmail.com',
      imapPort: 993,
      smtpHost: 'smtp.fastmail.com',
      smtpPort: 465,
      jmapEndpoint: 'https://api.fastmail.com/jmap/session',
      explanation: `Custom domain "${domain}" supports modern JMAP (HTTPS JSON Email API) and IMAP/SMTP.`,
    };
  }

  // Generic Custom Domain (GoDaddy, Namecheap, Zoho, Cloudflare, Self-Hosted Postfix/Dovecot, cPanel)
  return {
    domain,
    detectedProvider: 'custom-domain',
    providerLabel: `Custom Domain Mail Server (${domain})`,
    authMethod: 'jmap-imap-password',
    mxRecords: mxRecords.length ? mxRecords : [`mail.${domain}`],
    imapHost: `imap.${domain}`,
    imapPort: 993,
    smtpHost: `smtp.${domain}`,
    smtpPort: 465,
    jmapEndpoint: `https://jmap.${domain}/.well-known/jmap`,
    explanation: `Custom domain "${domain}" connects via Universal IMAP/SMTP or JMAP (RFC 8620). Auto-filled server hostnames for @${domain}.`,
  };
}

/**
 * Launches Google Identity Services (`google.accounts.oauth2.initTokenClient`) if available,
 * or falls back to a centered OAuth2 popup window, then automatically fetches the user's
 * Google email and profile name so signup is 1-click.
 */
export async function launchRealOAuthPopup(params: {
  provider: 'google' | 'microsoft';
  clientId: string;
  loginHint?: string;
}): Promise<OAuthSignInResult> {
  const { provider, clientId, loginHint } = params;
  const redirectUri = window.location.origin;
  const state = `atme_oauth_${Date.now().toString(36)}`;

  // 1. If Google provider, try official Google Identity Services Token Client first
  if (provider === 'google') {
    const gisLoaded = await loadGoogleIdentityServicesScript();
    const gsiOAuth2 = (
      window as unknown as {
        google?: {
          accounts?: {
            oauth2?: {
              initTokenClient: (config: {
                client_id: string;
                scope: string;
                hint?: string;
                prompt?: string;
                callback: (response: {
                  access_token?: string;
                  expires_in?: number;
                  scope?: string;
                  error?: string;
                  error_description?: string;
                }) => void;
                error_callback?: (err: { type?: string; message?: string }) => void;
              }) => { requestAccessToken: (override?: { prompt?: string }) => void };
            };
          };
        };
      }
    ).google?.accounts?.oauth2;

    if (gisLoaded && gsiOAuth2) {
      return new Promise<OAuthSignInResult>((resolve, reject) => {
        const tokenClient = gsiOAuth2.initTokenClient({
          client_id: clientId,
          scope: GOOGLE_OAUTH_SCOPES,
          hint: loginHint,
          prompt: 'select_account',
          callback: async (resp) => {
            if (resp.error || !resp.access_token) {
              reject(
                new Error(
                  resp.error_description ||
                    resp.error ||
                    'Google OAuth authorization was cancelled.'
                )
              );
              return;
            }
            try {
              const userProfile = await fetchGoogleUserProfile(resp.access_token);
              saveGoogleOAuthSession({
                email: userProfile.email,
                accessToken: resp.access_token,
                expiresAtMs: Date.now() + (resp.expires_in || 3500) * 1000,
              });
              resolve({
                accessToken: resp.access_token,
                expiresInSeconds: resp.expires_in,
                scope: resp.scope,
                userProfile,
              });
            } catch {
              resolve({
                accessToken: resp.access_token,
                expiresInSeconds: resp.expires_in,
                scope: resp.scope,
              });
            }
          },
          error_callback: (err) => {
            reject(
              new Error(
                err?.message ||
                  `Google Sign-In popup closed (${err?.type || 'cancelled'})`
              )
            );
          },
        });

        tokenClient.requestAccessToken({ prompt: 'select_account' });
      });
    }
  }

  // 2. Fallback: Direct OAuth2 Popup Window
  let authUrl = '';
  if (provider === 'google') {
    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'token',
      scope: GOOGLE_OAUTH_SCOPES,
      state,
      include_granted_scopes: 'true',
      prompt: 'select_account',
    });
    if (loginHint) query.set('login_hint', loginHint);
    authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${query.toString()}`;
  } else {
    const { codeChallenge } = await generatePkceChallengePair();
    const scope = [
      'openid',
      'profile',
      'email',
      'https://graph.microsoft.com/Mail.ReadWrite',
      'https://graph.microsoft.com/Mail.Send',
    ].join(' ');

    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'token',
      scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      prompt: 'select_account',
    });
    if (loginHint) query.set('login_hint', loginHint);
    authUrl = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?${query.toString()}`;
  }

  const width = 520;
  const height = 640;
  const left = Math.round(window.screenX + (window.outerWidth - width) / 2);
  const top = Math.round(window.screenY + (window.outerHeight - height) / 2);

  const popup = window.open(
    authUrl,
    'AtmeOAuthPopup',
    `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`
  );

  if (!popup) {
    throw new Error(
      'Popup blocked by browser. Please allow popups for this site.'
    );
  }

  return new Promise((resolve, reject) => {
    const timer = window.setInterval(async () => {
      try {
        if (popup.closed) {
          window.clearInterval(timer);
          reject(new Error('OAuth sign-in popup was closed before completion.'));
          return;
        }
        if (popup.location.origin === redirectUri && popup.location.hash) {
          const hashParams = new URLSearchParams(
            popup.location.hash.replace(/^#/, '')
          );
          const token = hashParams.get('access_token');
          const expiresIn = Number(hashParams.get('expires_in') || '3600');
          if (token) {
            window.clearInterval(timer);
            popup.close();
            if (provider === 'google') {
              try {
                const userProfile = await fetchGoogleUserProfile(token);
                saveGoogleOAuthSession({
                  email: userProfile.email,
                  accessToken: token,
                  expiresAtMs: Date.now() + expiresIn * 1000,
                });
                resolve({
                  accessToken: token,
                  expiresInSeconds: expiresIn,
                  userProfile,
                });
                return;
              } catch {
                // Fall through with token only
              }
            }
            resolve({ accessToken: token, expiresInSeconds: expiresIn });
          }
        }
      } catch {
        // Cross-origin while user is still on accounts.google.com / login.microsoftonline.com
      }
    }, 350);
  });
}
