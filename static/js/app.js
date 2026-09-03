const searchInput = document.querySelector("#member-search");
const memberCards = [...document.querySelectorAll(".member-card")];
const memberCount = document.querySelector("#member-count");
const emptyState = document.querySelector("#empty-state");

searchInput?.addEventListener("input", () => {
  const query = searchInput.value.trim().toLowerCase();
  let visible = 0;
  memberCards.forEach((card) => {
    const matches = card.dataset.search.toLowerCase().includes(query);
    card.hidden = !matches;
    if (matches) visible += 1;
  });
  memberCount.textContent = visible + " sample " + (visible === 1 ? "member" : "members");
  emptyState.hidden = visible !== 0;
});

document.querySelectorAll(".profile-button").forEach((button) => {
  button.addEventListener("click", () => document.querySelector("#" + button.dataset.dialog).showModal());
});
document.querySelectorAll(".profile-dialog").forEach((dialog) => {
  dialog.querySelector(".close-dialog").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
});
