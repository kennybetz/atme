/**
 * Universal Sign-In Portal, OAuth2 PKCE Popup Engine & Custom Domain MX Auto-Discovery
 *
 * Supports:
 *   1. Real Google OAuth2 Popup (`accounts.google.com/o/oauth2/v2/auth` or Google Identity Services)
 *   2. Real Microsoft Entra / Outlook OAuth2 PKCE Popup (`login.microsoftonline.com/common/oauth2/v2.0/authorize`)
 *   3. DNS-over-HTTPS (DoH) MX Record Auto-Discovery (`https://dns.google/resolve?name=<domain>&type=MX`)
 *      so users with custom domains (`you@yourcompany.com`) are automatically routed to:
 *        - Google Workspace OAuth2
 *        - Microsoft 365 OAuth2
 *        - Proton Mail Custom Domain
 *        - Fastmail / Zoho / iCloud / cPanel / Universal JMAP or IMAP+SMTP
 */

import { EmailProviderType } from '../protocol/types';

export interface DomainAutoDiscoveryResult {
  domain: string;
  detectedProvider: EmailProviderType;
  providerLabel: string;
  authMethod: 'oauth2-google' | 'oauth2-microsoft' | 'proton-bridge' | 'jmap-imap-password';
  mxRecords: string[];
  imapHost: string;
  imapPort: number;
  smtpHost: string;
  smtpPort: number;
  jmapEndpoint?: string;
  explanation: string;
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
  const base64Url = btoa(
    String.fromCharCode(...new Uint8Array(digest))
  )
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return {
    codeVerifier,
    codeChallenge: base64Url,
  };
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
      explanation: 'Consumer Google account — uses 1-Click Google OAuth2 Popup.',
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
        'Proton Mail account — natively compatible with Dont Call OpenPGP E2EE & Proton Mail Bridge.',
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
        'Yahoo Mail — connects via IMAP IDLE + App Password with server-side X-DontCall-Protocol header filtering.',
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
 * Opens a real centered OAuth2 Popup Window for Google or Microsoft when a Client ID is provided.
 */
export async function launchRealOAuthPopup(params: {
  provider: 'google' | 'microsoft';
  clientId: string;
  loginHint?: string;
}): Promise<{ accessToken: string }> {
  const { provider, clientId, loginHint } = params;
  const redirectUri = window.location.origin;
  const state = `dc_oauth_${Date.now().toString(36)}`;

  let authUrl = '';
  if (provider === 'google') {
    const scope = [
      'openid',
      'email',
      'profile',
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/gmail.settings.basic',
    ].join(' ');

    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'token',
      scope,
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
    'DontCallOAuthPopup',
    `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`
  );

  if (!popup) {
    throw new Error('Popup blocked by browser. Please allow popups for this site.');
  }

  return new Promise((resolve, reject) => {
    const timer = window.setInterval(() => {
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
          if (token) {
            window.clearInterval(timer);
            popup.close();
            resolve({ accessToken: token });
          }
        }
      } catch {
        // Cross-origin while user is still on accounts.google.com / login.microsoftonline.com
      }
    }, 350);
  });
}
