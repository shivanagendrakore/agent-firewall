/**
 * The extension manifest, from one source. `npm run build` writes it to
 * dist/manifest.json; manifest.test.ts and the e2e smoke test fail on any
 * permission beyond design section 11's install-time set.
 *
 * Optional permissions (design 11) are requested at the moment of use, never
 * at install. The native link adds `nativeMessaging` for the link to the local
 * firewall (design 10): the side panel asks for it only when the person turns
 * the link on. `debugger`, `management` and `tabGroups` are added here, with
 * the test, when their features are built.
 */

/** Design section 11, install-time permissions. Changing this list needs a design change first. */
export const INSTALL_PERMISSIONS = ["storage", "declarativeNetRequest", "downloads", "sidePanel", "webNavigation"] as const;

/** Design section 11, optional permissions: requested at runtime only, from our own UI, with an explanation. */
export const OPTIONAL_PERMISSIONS = ["nativeMessaging"] as const;

/** The content guard and gate must run on every page and frame (design 11). */
export const HOST_PERMISSIONS = ["<all_urls>"] as const;

/** Built file names, shared with the build script and the e2e harness. */
export const FILES = {
  worker: "worker.js",
  content: "content.js",
  sidePanel: "sidepanel.html",
  popup: "popup.html",
  /** The navigation policy's static ruleset (engine/nav-rules.ts ALWAYS_RULES), written by the build. */
  rules: "rules.json",
  /** The explanation page a blocked navigation lands on; opened by the worker with tabs.update, never web accessible. */
  blocked: "blocked.html",
} as const;

/** Toolbar and store icon sizes; the files are icons/icon-{size}.png (the LaunchSafe mark, committed) and the build copies them to dist/icons/. */
export const ICON_SIZES = [16, 32, 48, 128] as const;
const icons = Object.fromEntries(ICON_SIZES.map((s) => [String(s), `icons/icon-${s}.png`]));

/** The store listing's summary (store/listing.md), used as the manifest description: it states the limits honestly. */
export const DESCRIPTION = "In agent mode, makes an AI browser agent ask you before it buys, sends, grants access or leaks data. Runs on your device.";
export const NAME = "LaunchSafe Agent Firewall for browsers";

/** The extension pages' content security policy (m11). */
export const EXTENSION_PAGES_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/** Chrome 121: checkVisibility({ opacityProperty, visibilityProperty }) and a stable side panel API. */
export const MINIMUM_CHROME_VERSION = "121";

export interface ManifestOptions {
  version: string;
  /**
   * Test builds only (scripts/build.mjs with LAUNCHSAFE_E2E_NATIVE=1, into a temp folder): nativeMessaging
   * is granted at install, because Playwright cannot answer the browser's permission prompt. The product
   * build never sets it (manifest.test.ts, build.test.ts).
   */
  e2eGrantNativeMessaging?: boolean;
}

export function buildManifest(opts: ManifestOptions): chrome.runtime.ManifestV3 {
  return {
    manifest_version: 3,
    name: NAME,
    short_name: "LaunchSafe",
    description: DESCRIPTION,
    icons,
    version: opts.version,
    minimum_chrome_version: MINIMUM_CHROME_VERSION,
    permissions: opts.e2eGrantNativeMessaging === true ? [...INSTALL_PERMISSIONS, ...OPTIONAL_PERMISSIONS] : [...INSTALL_PERMISSIONS],
    optional_permissions: opts.e2eGrantNativeMessaging === true ? [] : [...OPTIONAL_PERMISSIONS],
    host_permissions: [...HOST_PERMISSIONS],
    background: { service_worker: FILES.worker, type: "module" },
    content_scripts: [
      {
        matches: ["<all_urls>"],
        js: [FILES.content],
        run_at: "document_start",
        all_frames: true,
        match_origin_as_fallback: true,
      },
    ],
    side_panel: { default_path: FILES.sidePanel },
    // Navigation policy (design 7): the always-on rows ship as a static ruleset; agent-mode rows are session rules.
    declarative_net_request: { rule_resources: [{ id: "always", enabled: true, path: FILES.rules }] },
    action: { default_title: "LaunchSafe Agent Firewall", default_popup: FILES.popup, default_icon: icons },
    // Extension pages: our own bundled scripts and stylesheet only, no inline style or script, no remote code, no
    // network requests, no forms, nothing may frame them (design 13; m11). There are no web_accessible_resources.
    content_security_policy: { extension_pages: EXTENSION_PAGES_CSP },
  } as chrome.runtime.ManifestV3;
}
