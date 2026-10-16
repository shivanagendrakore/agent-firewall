/**
 * The explanation page a blocked navigation lands on (design 7). The worker
 * opens it with tabs.update after one of our declarativeNetRequest rules
 * blocked a top-level navigation, passing the rule and the destination host
 * only (the path and query may carry the person's data, so they never reach
 * this page; only their length does).
 *
 * It explains and offers no approval: the page is in the tab the agent is
 * driving, so anything clickable here could be clicked by the agent. Every
 * value is written with textContent.
 */
import { explanationFor } from "./blocked-view.js";

const params = new URLSearchParams(location.search);
const view = explanationFor({ rule: params.get("rule") ?? "", host: params.get("host") ?? "", chars: params.get("chars") ?? "", approval: params.get("approval") ?? "" });

const set = (id: string, text: string) => {
  const el = document.getElementById(id);
  if (el !== null) el.textContent = text;
};
set("title", view.title);
set("why", view.why);
set("host", view.host);
set("chars", view.chars);
set("rule", view.rule);
set("next", view.next);
document.title = `${view.title} - LaunchSafe Agent Firewall`;
