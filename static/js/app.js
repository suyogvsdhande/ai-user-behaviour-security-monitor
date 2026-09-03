const searchInput = document.querySelector("#member-search");
const memberCards = [...document.querySelectorAll(".member-card")];
const memberCount = document.querySelector("#member-count");
const emptyState = document.querySelector("#empty-state");
const makeId = () => crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
const sessionId = sessionStorage.getItem("sentinelSessionId") || makeId();
const deviceId = localStorage.getItem("sentinelDemoDeviceId") || makeId();
const pageEnteredAt = Date.now();
let searchTimer;
sessionStorage.setItem("sentinelSessionId", sessionId);
localStorage.setItem("sentinelDemoDeviceId", deviceId);
const eventPayload = (action, details = {}) => ({action, session_id: sessionId, device_id: deviceId, screen_name: "Member Directory", ...details});
function logEvent(action, details = {}) {
  return fetch("/api/events", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(eventPayload(action, details)), keepalive: true}).catch(() => undefined);
}
logEvent("PAGE_ENTER");
searchInput?.addEventListener("input", () => {
  const query = searchInput.value.trim().toLowerCase(); let visible = 0;
  memberCards.forEach((card) => { const matches = card.dataset.search.toLowerCase().includes(query); card.hidden = !matches; if (matches) visible += 1; });
  memberCount.textContent = visible + " sample " + (visible === 1 ? "member" : "members"); emptyState.hidden = visible !== 0;
  clearTimeout(searchTimer); searchTimer = setTimeout(() => logEvent("SEARCH", {search_query: searchInput.value.trim()}), 600);
});
document.querySelectorAll(".profile-button").forEach((button) => button.addEventListener("click", async () => { const response = await logEvent("PROFILE_VIEW", {profile_id: button.dataset.profileId}); if (response?.ok) document.querySelector("#" + button.dataset.dialog).showModal(); else if (response) alert("This profile view is restricted by the security policy."); }));
document.querySelectorAll(".profile-dialog").forEach((dialog) => { dialog.querySelector(".close-dialog").addEventListener("click", () => dialog.close()); dialog.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); }); });
document.addEventListener("copy", () => logEvent("COPY_ATTEMPT"));
document.querySelectorAll(".download-button").forEach((link) => link.addEventListener("click", () => { const url = new URL(link.href); url.searchParams.set("session_id", sessionId); url.searchParams.set("device_id", deviceId); link.href = url.toString(); }));
window.addEventListener("pagehide", () => { const duration_seconds = Math.max(0, (Date.now() - pageEnteredAt) / 1000); navigator.sendBeacon("/api/events", new Blob([JSON.stringify(eventPayload("PAGE_EXIT", {duration_seconds}))], {type: "application/json"})); });
