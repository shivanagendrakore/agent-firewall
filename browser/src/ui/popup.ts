/**
 * Toolbar popup: status, and the control that opens the side panel (the side
 * panel can only be opened from a person's gesture in our own UI).
 */
import { sendToWorker } from "../shared/bridge.js";
import { modeLine, pendingLine } from "./view.js";

function setText(id: string, text: string): void {
  const el = document.getElementById(id);
  if (el !== null) el.textContent = text;
}

sendToWorker({ type: "ui.state" }).then(
  (s) => {
    setText("mode", modeLine(s));
    setText("pending", pendingLine(s));
  },
  () => setText("mode", "The extension's worker is not responding. Reload the extension."),
);

// The window id is read up front so the click handler can call sidePanel.open synchronously, inside the gesture.
let windowId: number | undefined;
void chrome.windows.getCurrent().then((w) => (windowId = w.id));
document.getElementById("open-panel")?.addEventListener("click", () => {
  if (windowId === undefined) return;
  chrome.sidePanel.open({ windowId }).then(
    () => window.close(),
    () => setText("pending", "Could not open the side panel. Right-click the LaunchSafe icon and choose Open side panel."),
  );
});
