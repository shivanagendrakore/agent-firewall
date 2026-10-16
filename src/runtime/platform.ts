/**
 * Which operating systems the firewall runs on: macOS and Linux (docs/limitations.md). Windows is not
 * supported: hooks there run through a different shell, the file rules and sandboxes are written for POSIX
 * paths, and nothing has been tested there. An unsupported platform must fail closed and say so, never run
 * half-working: the hook blocks the action (exit 2), the other commands and the Node library refuse.
 * The platform is a parameter everywhere so a test can simulate one without touching process.platform.
 */

const SUPPORTED: readonly NodeJS.Platform[] = ["darwin", "linux"];

export function platformSupported(platform: NodeJS.Platform = process.platform): boolean {
  return SUPPORTED.includes(platform);
}

/** How a platform is named to a person ("Windows (win32)": Node's own name is not what they call it). */
function platformName(platform: NodeJS.Platform): string {
  return platform === "win32" ? "Windows (win32)" : platform;
}

/** The sentence every refusal starts with. */
export function unsupportedPlatformMessage(platform: NodeJS.Platform = process.platform): string {
  return `LaunchSafe Firewall supports macOS and Linux only. ${platformName(platform)} is not supported, and nothing in it has been tested there.`;
}

/** Throws the refusal unless `platform` is supported. */
export function assertSupportedPlatform(platform: NodeJS.Platform = process.platform): void {
  if (!platformSupported(platform)) throw new Error(unsupportedPlatformMessage(platform));
}
