/**
 * The downloads gate (design 5.2 `download_exec`).
 *
 * Chrome decides a download's file name before the file lands at its final
 * path, and waits for extensions listening to
 * `downloads.onDeterminingFilename`. There, an executable or installer
 * (engine `isExecutableDownload`, by the offered file name, the URL's last
 * path segment and the MIME type) is cancelled at once, so no complete file
 * is ever written, and the worker asks for an approval. Once a person
 * approves, the worker downloads the same URL again, exactly once: the URL is
 * allowed for one download started by this extension, then forgotten.
 *
 * What it cannot do: the first request for the file has already been sent
 * when Chrome tells us about it (the server sees it), and a file the person
 * already has on disk is out of reach. Both are listed in the UI.
 */
import { isExecutableDownload } from "../engine/classify.js";
import { originOf } from "../engine/domain.js";
import { valuesDigest, type ActionSnapshot } from "../engine/fingerprint.js";

/** The fields of chrome.downloads.DownloadItem the gate reads. */
export interface DownloadItemLike {
  id: number;
  url: string;
  finalUrl?: string;
  filename: string;
  mime?: string;
  byExtensionId?: string;
  tabId?: number;
}

export interface OfferedDownload {
  url: string;
  filename: string;
  mime: string;
  tabId?: number;
}

const ALLOW_ONCE_MS = 60_000;

function lastSegment(url: string): string {
  try {
    return decodeURIComponent(new URL(url).pathname.split("/").pop() ?? "");
  } catch {
    return "";
  }
}

export function isExecutableItem(item: DownloadItemLike): boolean {
  const base = item.filename.split(/[\\/]/).pop() ?? "";
  const mime = item.mime ?? "";
  return isExecutableDownload(base, mime) || isExecutableDownload(lastSegment(item.finalUrl ?? item.url), "") || isExecutableDownload(lastSegment(item.url), "");
}

/** The snapshot a download approval binds to: the URL, the offered name and type; no tab or frame (the worker replays it). */
export function downloadSnapshot(d: OfferedDownload): ActionSnapshot {
  const origin = originOf(d.url) ?? "";
  return {
    tabId: -1,
    frameId: -1,
    frameOrigin: origin,
    kind: "download",
    actionClass: "download_exec",
    elementPath: `download:${d.url}`.slice(0, 2048),
    fieldNames: ["url", "filename", "mime"],
    valuesDigest: valuesDigest([
      { name: "url", type: "url", value: d.url },
      { name: "filename", type: "text", value: d.filename },
      { name: "mime", type: "text", value: d.mime },
    ]),
    targetOrigin: origin,
    method: "GET",
  };
}

export interface DownloadGate {
  /**
   * The body of the onDeterminingFilename listener. Returns the offered
   * download when the gate held (cancelled) it, null when it may proceed.
   */
  intercept(item: DownloadItemLike): OfferedDownload | null;
  /** The worker is about to download an approved URL itself: let exactly one such download through. */
  allowOnce(url: string): void;
}

/**
 * The onDeterminingFilename listener (I10). For a held download it returns true, which tells Chrome to wait for
 * `suggest` before it settles the name, so nothing is written under the final name while we act; it cancels the
 * download, and only after the cancel has gone through calls `suggest()` (with no name) to let Chrome finish its
 * bookkeeping for the cancelled item. Without the `true`, Chrome would settle the name and keep writing while the
 * cancel was still on its way. A download we let through returns nothing (Chrome picks the name itself).
 */
export function holdOnDeterminingFilename(
  gate: DownloadGate,
  io: { cancel: (id: number) => Promise<void>; hold: (d: OfferedDownload) => void },
): (item: DownloadItemLike, suggest: (s?: { filename: string }) => void) => boolean | undefined {
  return (item, suggest) => {
    const held = gate.intercept(item);
    if (held === null) return undefined;
    const release = (): void => {
      try {
        suggest();
      } catch {
        // Chrome already moved on (the item is gone): nothing to release.
      }
    };
    io.cancel(item.id).then(release, release);
    io.hold(held);
    return true;
  };
}

export function createDownloadGate(opts: { extensionId: string; now?: () => number }): DownloadGate {
  const now = opts.now ?? Date.now;
  const allowed = new Map<string, number>();
  return {
    intercept(item) {
      if (!isExecutableItem(item)) return null;
      if (item.byExtensionId === opts.extensionId) {
        for (const url of [item.url, item.finalUrl]) {
          if (url === undefined) continue;
          const until = allowed.get(url);
          if (until !== undefined) {
            allowed.delete(url);
            if (now() <= until) return null;
          }
        }
      }
      const url = !isExecutableDownload(lastSegment(item.url), "") && item.finalUrl !== undefined && isExecutableDownload(lastSegment(item.finalUrl), "") ? item.finalUrl : item.url;
      return { url, filename: item.filename.split(/[\\/]/).pop() ?? item.filename, mime: item.mime ?? "", ...(item.tabId !== undefined ? { tabId: item.tabId } : {}) };
    },
    allowOnce(url) {
      allowed.set(url, now() + ALLOW_ONCE_MS);
    },
  };
}
