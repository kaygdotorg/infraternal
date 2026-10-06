/** Boots the minimal static S1 tracer client. */
const app = document.querySelector<HTMLElement>("#app");
if (!app) throw new Error("tracer mount point is missing");
app.textContent = "Tracer client ready";
