import { Code2, Globe, Link2, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { SiteKey, Sites } from '../lib/types';
import { buildShareUrl } from '../lib/urlState';
import { CopyButton } from './ui';

export function ShareSubpageModal({
  isOpen,
  onClose,
  scenarioId,
  tab,
  initiator,
  sites,
  embedMode,
  onToggleEmbed,
}: {
  isOpen: boolean;
  onClose: () => void;
  scenarioId: string;
  tab: string;
  initiator: SiteKey;
  sites: Sites;
  embedMode: boolean;
  onToggleEmbed: (embed: boolean) => void;
}) {
  const [includeFullConfig, setIncludeFullConfig] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState<'url' | 'iframe' | 'hosting'>('url');

  const directUrl = useMemo(() => {
    return buildShareUrl({
      scenarioId,
      tab,
      initiator,
      embed: false,
      sites,
      includeConfig: includeFullConfig,
    });
  }, [scenarioId, tab, initiator, sites, includeFullConfig]);

  const embedUrl = useMemo(() => {
    return buildShareUrl({
      scenarioId,
      tab,
      initiator,
      embed: true,
      sites,
      includeConfig: includeFullConfig,
    });
  }, [scenarioId, tab, initiator, sites, includeFullConfig]);

  const iframeSnippet = useMemo(() => {
    return `<iframe\n  src="${embedUrl || 'https://yourwebsite.com/tools/vpn/?embed=1'}"\n  width="100%"\n  height="920"\n  style="border: none; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.3);"\n  title="IPSEC VPN Simulator"\n  loading="lazy"\n  allow="clipboard-write"\n></iframe>`;
  }, [embedUrl]);

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="subpage-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-ink/80 backdrop-blur-sm animate-rise"
      onClick={onClose}
    >
      <div
        className="relative flex flex-col w-full max-w-[680px] max-h-[90vh] overflow-hidden rounded-xl border border-line bg-panel shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-line px-4 py-3 sm:px-6">
          <div className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-a" aria-hidden />
            <div>
              <h2 id="subpage-modal-title" className="text-[15px] font-semibold text-fg">
                Open as Subpage on Your Website
              </h2>
              <p className="text-[12px] text-mute">
                Deep-link URL, iframe embed code, and subfolder hosting guide
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="grid h-8 w-8 place-items-center rounded-md text-mute transition-colors hover:bg-raised hover:text-fg"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Modal Navigation */}
        <div className="flex border-b border-line bg-well/40 px-4 sm:px-6">
          <button
            type="button"
            onClick={() => setActiveSubTab('url')}
            className={`flex items-center gap-1.5 py-2.5 px-3 text-[13px] font-medium border-b-2 transition-colors ${
              activeSubTab === 'url' ? 'border-a text-fg' : 'border-transparent text-mute hover:text-fg'
            }`}
          >
            <Link2 className="h-4 w-4" />
            <span>Direct Subpage URL</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveSubTab('iframe')}
            className={`flex items-center gap-1.5 py-2.5 px-3 text-[13px] font-medium border-b-2 transition-colors ${
              activeSubTab === 'iframe' ? 'border-a text-fg' : 'border-transparent text-mute hover:text-fg'
            }`}
          >
            <Code2 className="h-4 w-4" />
            <span>Iframe Embed</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveSubTab('hosting')}
            className={`flex items-center gap-1.5 py-2.5 px-3 text-[13px] font-medium border-b-2 transition-colors ${
              activeSubTab === 'hosting' ? 'border-a text-fg' : 'border-transparent text-mute hover:text-fg'
            }`}
          >
            <Globe className="h-4 w-4" />
            <span>Hosting Guide</span>
          </button>
        </div>

        {/* Modal Content */}
        <div className="thin-scroll flex-1 overflow-y-auto p-4 sm:p-6 space-y-4 text-[13px]">
          {activeSubTab === 'url' && (
            <div className="space-y-4">
              <div>
                <label className="block text-[11.5px] font-semibold uppercase tracking-wider text-mute mb-1">
                  Shareable Subpage URL (Opens Current State)
                </label>
                <div className="flex items-center gap-2 rounded-lg border border-line bg-term p-2">
                  <input
                    type="text"
                    readOnly
                    value={directUrl}
                    className="min-w-0 flex-1 border-0 bg-transparent font-mono text-[12px] text-fg outline-none select-all"
                  />
                  <CopyButton text={directUrl} label="Copy URL" />
                </div>
              </div>

              <div className="rounded-lg border border-line bg-well/50 p-3 space-y-2">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeFullConfig}
                    onChange={(e) => setIncludeFullConfig(e.target.checked)}
                    className="h-4 w-4 rounded border-line bg-well text-a focus:ring-0"
                  />
                  <span className="font-medium text-fg">
                    Encode full custom parameters (IPs, NAT, PSK, ciphers) into the URL
                  </span>
                </label>
                <p className="text-[12px] text-mute pl-6">
                  When enabled, any customized Site A and Site B settings are encoded into the URL, allowing recipients or website visitors to open your exact lab configuration.
                </p>
              </div>

              <div className="space-y-2 text-[12px] text-mute">
                <p className="font-medium text-fg text-[12.5px]">Supported URL Query Parameters:</p>
                <ul className="list-disc pl-5 space-y-1 font-mono text-[11.5px]">
                  <li>
                    <span className="text-a">?scenario=azure-branch</span> — opens a specific lab scenario
                  </li>
                  <li>
                    <span className="text-a">?tab=traffic</span> — jumps directly to <span className="text-fg">traffic</span>, <span className="text-fg">diagnosis</span>, <span className="text-fg">negotiation</span>, <span className="text-fg">compare</span>, or <span className="text-fg">config</span>
                  </li>
                  <li>
                    <span className="text-a">?init=B</span> — sets Site B as the tunnel initiator
                  </li>
                  <li>
                    <span className="text-a">?embed=1</span> — activates seamless embed mode (hides main navigation header for iframe integration)
                  </li>
                  <li>
                    <span className="text-a">?config=&lt;base64&gt;</span> — loads custom site configurations directly from the URL
                  </li>
                </ul>
              </div>
            </div>
          )}

          {activeSubTab === 'iframe' && (
            <div className="space-y-4">
              <div>
                <label className="block text-[11.5px] font-semibold uppercase tracking-wider text-mute mb-1">
                  Iframe Embed Code (Paste into your HTML, WordPress, or React page)
                </label>
                <div className="relative rounded-lg border border-line bg-term p-3 font-mono text-[12px]">
                  <pre className="whitespace-pre-wrap text-fg [overflow-wrap:anywhere] pr-20">{iframeSnippet}</pre>
                  <div className="absolute top-2.5 right-2.5">
                    <CopyButton text={iframeSnippet} label="Copy Code" />
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between rounded-lg border border-line bg-well/50 p-3">
                <div>
                  <div className="font-medium text-fg">Test Embed Mode in Browser</div>
                  <div className="text-[12px] text-mute">
                    Hides the top branding header and footer for a seamless subpage look.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => onToggleEmbed(!embedMode)}
                  className={`px-3 py-1.5 rounded-md font-mono text-[12px] font-medium border transition-colors ${
                    embedMode
                      ? 'border-ok/40 bg-ok/10 text-ok'
                      : 'border-line bg-raised text-mute hover:text-fg'
                  }`}
                >
                  {embedMode ? 'Embed Mode ON' : 'Embed Mode OFF'}
                </button>
              </div>

              <p className="text-[12px] text-mute">
                Tip: When hosting on your own domain (e.g. <span className="font-mono text-fg">https://yourdomain.com/tools/vpn/</span>), replace the iframe <span className="font-mono text-fg">src</span> attribute with your relative subpath or full URL.
              </p>
            </div>
          )}

          {activeSubTab === 'hosting' && (
            <div className="space-y-3.5 text-[12.5px] leading-relaxed">
              <div className="rounded-lg border border-line bg-well/50 p-3 space-y-1.5">
                <div className="font-semibold text-fg">Zero-Dependency Single File Architecture</div>
                <p className="text-mute text-[12px]">
                  The tool builds via <span className="font-mono text-fg">vite-plugin-singlefile</span> into a single, self-contained <span className="font-mono text-fg">dist/index.html</span> with all CSS, JavaScript, fonts, and icons inlined. There are no separate asset folders that can break with 404s when moved to a subfolder!
                </p>
              </div>

              <div>
                <h4 className="font-semibold text-fg text-[13px] mb-1">How to host it under a subpath on your website:</h4>
                <ol className="list-decimal pl-5 space-y-2 text-mute">
                  <li>
                    <span className="text-fg font-medium">Create a directory on your web server</span> (e.g. <span className="font-mono text-a">/var/www/yoursite/tools/vpn-simulator/</span> or in your CDN / S3 bucket).
                  </li>
                  <li>
                    <span className="text-fg font-medium">Copy the built <span className="font-mono text-a">dist/index.html</span></span> file into that folder (rename to <span className="font-mono text-a">index.html</span>).
                  </li>
                  <li>
                    <span className="text-fg font-medium">Open in your browser</span> at:
                    <div className="mt-1 font-mono text-[12px] text-ok bg-term p-2 rounded border border-line select-all">
                      https://yourwebsite.com/tools/vpn-simulator/
                    </div>
                  </li>
                  <li>
                    You can open any specific scenario or tab with URL parameters, for example:
                    <div className="mt-1 font-mono text-[11.5px] text-fg bg-term p-2 rounded border border-line select-all">
                      https://yourwebsite.com/tools/vpn-simulator/?scenario=azure-branch&tab=traffic
                    </div>
                  </li>
                </ol>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-line bg-well/40 px-4 py-3 sm:px-6">
          <span className="font-mono text-[11px] text-mute">
            {embedMode ? 'Currently in embed preview' : 'Standard standalone mode'}
          </span>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-8 items-center justify-center rounded-md bg-fg px-3.5 text-[12.5px] font-semibold text-ink transition-colors hover:bg-white"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
