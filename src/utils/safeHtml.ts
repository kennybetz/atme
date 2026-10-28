/**
 * Safe HTML Sanitizer Utility
 *
 * Uses the native Browser Sanitizer API (`Element.prototype.setHTML`) when supported,
 * with a lazy-loaded DOMPurify fallback configured to match native Sanitizer rules.
 */

let domPurifyPromise: Promise<typeof import('dompurify').default> | undefined;

function loadDOMPurify() {
  domPurifyPromise ??= import('dompurify').then((mod) => mod.default ?? mod);
  return domPurifyPromise;
}

export async function safeSetInviteHTML(
  el: HTMLElement,
  html: string
): Promise<void> {
  const elements = [
    'div',
    'h2',
    'p',
    'strong',
    'code',
    'a',
    'span',
  ];
  const attributes = ['class', 'href', 'target', 'rel'];

  if ('setHTML' in Element.prototype) {
    (
      el as HTMLElement & {
        setHTML: (
          input: string,
          options: {
            sanitizer: { elements: string[]; attributes: string[] };
          }
        ) => void;
      }
    ).setHTML(html, {
      sanitizer: { elements, attributes },
    });
  } else {
    const DOMPurify = await loadDOMPurify();
    el.innerHTML = DOMPurify.sanitize(html, {
      ALLOWED_TAGS: [...elements, '#text'],
      ALLOWED_ATTR: attributes,
      ALLOW_ARIA_ATTR: false,
      ALLOW_DATA_ATTR: false,
      KEEP_CONTENT: false,
    });
  }
}
