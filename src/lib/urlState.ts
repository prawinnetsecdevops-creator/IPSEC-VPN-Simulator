import { SCENARIOS } from './scenarios';
import type { SiteKey, Sites, VendorId } from './types';
import { VENDORS, coerce } from './vendors';

export interface UrlParams {
  scenarioId?: string;
  tab?: 'negotiation' | 'diagnosis' | 'compare' | 'traffic' | 'config';
  initiator?: SiteKey;
  embed?: boolean;
  autorun?: boolean;
  vendorA?: VendorId;
  vendorB?: VendorId;
  customState?: {
    sites: Sites;
    initiator: SiteKey;
  };
}

/** Encode state into URL query parameter string */
export function encodeConfigToParam(sites: Sites, initiator: SiteKey): string {
  try {
    const json = JSON.stringify({ A: sites.A, B: sites.B, init: initiator });
    return btoa(unescape(encodeURIComponent(json)));
  } catch {
    return '';
  }
}

/** Decode state from URL query parameter string */
export function decodeConfigFromParam(param: string): { sites: Sites; initiator: SiteKey } | null {
  try {
    const json = decodeURIComponent(escape(atob(param)));
    const parsed = JSON.parse(json);
    if (parsed && parsed.A && parsed.B) {
      return {
        sites: {
          A: coerce({ ...parsed.A, key: 'A' }),
          B: coerce({ ...parsed.B, key: 'B' }),
        },
        initiator: parsed.init === 'B' ? 'B' : 'A',
      };
    }
  } catch {
    // invalid or corrupted state
  }
  return null;
}

/** Parse current browser URL for deep-linking parameters */
export function parseUrlState(): UrlParams {
  if (typeof window === 'undefined') return {};

  const search = new URLSearchParams(window.location.search);
  const hash = window.location.hash.replace(/^#/, '');
  const hashParams = new URLSearchParams(hash.includes('=') ? hash : `scenario=${hash}`);

  const get = (key: string) => search.get(key) || hashParams.get(key);

  const scenarioParam = get('scenario') || get('s');
  const validScenario = SCENARIOS.find((s) => s.id === scenarioParam)?.id;

  const tabParam = (get('tab') || get('t'))?.toLowerCase();
  const validTabs = ['negotiation', 'diagnosis', 'compare', 'traffic', 'config'] as const;
  const tab = validTabs.find((t) => t === tabParam);

  const initParam = get('init') || get('initiator');
  const initiator = initParam === 'B' || initParam === 'b' ? 'B' : initParam === 'A' || initParam === 'a' ? 'A' : undefined;

  const embedParam = get('embed') || get('embedded') || get('iframe');
  const embed = embedParam === '1' || embedParam === 'true' || embedParam === 'yes';

  const autorunParam = get('autorun') || get('run');
  const autorun = autorunParam === '1' || autorunParam === 'true' || autorunParam === 'yes';

  const vendorAParam = get('vendorA') || get('vA');
  const vendorA = vendorAParam && vendorAParam in VENDORS ? (vendorAParam as VendorId) : undefined;

  const vendorBParam = get('vendorB') || get('vB');
  const vendorB = vendorBParam && vendorBParam in VENDORS ? (vendorBParam as VendorId) : undefined;

  const configParam = get('config') || get('state');
  const customState = configParam ? decodeConfigFromParam(configParam) ?? undefined : undefined;

  return {
    scenarioId: validScenario,
    tab,
    initiator,
    embed,
    autorun,
    vendorA,
    vendorB,
    customState,
  };
}

/** Update the browser's address bar without reloading */
export function updateBrowserUrl(params: {
  scenarioId: string;
  tab: string;
  initiator: SiteKey;
  embed: boolean;
}) {
  if (typeof window === 'undefined') return;

  try {
    const url = new URL(window.location.href);
    if (params.scenarioId && params.scenarioId !== 'baseline') {
      url.searchParams.set('scenario', params.scenarioId);
    } else {
      url.searchParams.delete('scenario');
    }

    if (params.tab && params.tab !== 'negotiation') {
      url.searchParams.set('tab', params.tab);
    } else {
      url.searchParams.delete('tab');
    }

    if (params.initiator === 'B') {
      url.searchParams.set('init', 'B');
    } else {
      url.searchParams.delete('init');
    }

    if (params.embed) {
      url.searchParams.set('embed', '1');
    } else {
      url.searchParams.delete('embed');
    }

    window.history.replaceState({}, '', url.toString());
  } catch {
    // ignore in sandboxed environments
  }
}

/** Build shareable URL string for current state */
export function buildShareUrl(options: {
  scenarioId?: string;
  tab?: string;
  initiator?: SiteKey;
  embed?: boolean;
  sites?: Sites;
  includeConfig?: boolean;
}): string {
  if (typeof window === 'undefined') return '';

  const url = new URL(window.location.href);
  // Clear any existing query params
  url.search = '';
  url.hash = '';

  if (options.includeConfig && options.sites && options.initiator) {
    const encoded = encodeConfigToParam(options.sites, options.initiator);
    if (encoded) url.searchParams.set('config', encoded);
  } else if (options.scenarioId && options.scenarioId !== 'baseline') {
    url.searchParams.set('scenario', options.scenarioId);
  }

  if (options.tab && options.tab !== 'negotiation') {
    url.searchParams.set('tab', options.tab);
  }

  if (options.initiator === 'B' && !options.includeConfig) {
    url.searchParams.set('init', 'B');
  }

  if (options.embed) {
    url.searchParams.set('embed', '1');
  }

  return url.toString();
}
