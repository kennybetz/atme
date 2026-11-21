/**
 * Client-Side Rich Link Preview Extractor (`@me/simple`).
 *
 * Parses the first HTTP/HTTPS URL in a message locally on the sender's device
 * before building the outbound `ATME/1.0` MIME packet, preventing server-side
 * link-unfurling pings or third-party tracking.
 */

import { DcpLinkPreview } from '../protocol/types';

/**
 * Extracts a lightweight, privacy-preserving link preview card from plain text.
 * Returns `undefined` when no valid HTTP(S) URL is present.
 */
export function extractClientSideLinkPreview(
  text: string
): DcpLinkPreview | undefined {
  const match = text.match(/https?:\/\/[^\s<>")]+/i);
  if (!match) return undefined;

  try {
    const parsed = new URL(match[0]);
    const host = parsed.hostname.replace(/^www\./i, '').toLowerCase();
    const pathSlug = parsed.pathname
      .split('/')
      .filter(Boolean)
      .join(' › ');

    const knownCatalog: Record<
      string,
      { siteName: string; title: string; description: string; themeColor: string }
    > = {
      'github.com': {
        siteName: 'GitHub',
        title: pathSlug
          ? `Repository • ${pathSlug}`
          : 'GitHub — Open Source Code & Repositories',
        description:
          'Client-side preview • Zero server tracking or link unfurling ping.',
        themeColor: '#238636',
      },
      'proton.me': {
        siteName: 'Proton Privacy',
        title: 'Proton Mail & OpenPGP End-to-End Encryption',
        description:
          'Compatible with @me ATME/1.0 interoperable OpenPGP packets.',
        themeColor: '#6d4aff',
      },
      'signal.org': {
        siteName: 'Signal Documentation',
        title: 'Cryptographic Specifications',
        description: 'Open messaging protocol references and specifications.',
        themeColor: '#3a76f0',
      },
      'figma.com': {
        siteName: 'Figma Design',
        title: pathSlug ? `Design File • ${pathSlug}` : 'Shared Figma Prototype',
        description: 'Design link preview generated locally before send.',
        themeColor: '#a259ff',
      },
    };

    const preset = knownCatalog[host];
    return {
      url: parsed.toString(),
      domain: host,
      siteName: preset?.siteName || host.toUpperCase(),
      title:
        preset?.title ||
        (pathSlug ? `${host} — ${pathSlug}` : `Link • ${host}`),
      description:
        preset?.description ||
        `Unfurled locally on sender device (${parsed.origin}).`,
      themeColor: preset?.themeColor || '#0a84ff',
    };
  } catch {
    return undefined;
  }
}
