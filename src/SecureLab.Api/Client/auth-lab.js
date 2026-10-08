import { apiFetch } from "./api-fetch.js";

const result = document.querySelector("#result");

async function refreshSessionState() {
  const response = await apiFetch("/api/me");
  if (response.ok) {
    const profile = await response.json();
    document.querySelector("#state-msg").textContent = "Сеанс активний";
    document.querySelector("#profile-data").textContent = JSON.stringify(
      profile,
      null,
      2,
    );
    document.querySelector("#login-form").hidden = true;
    document.querySelector("#register-form").hidden = true;
    document.querySelector("#incident-form").hidden = false;
    document.querySelector("#logout").hidden = false;
  } else {
    document.querySelector("#state-msg").textContent = "Не ввійшли";
    document.querySelector("#profile-data").textContent = "";
    document.querySelector("#login-form").hidden = false;
    document.querySelector("#register-form").hidden = false;
    document.querySelector("#incident-form").hidden = true;
    document.querySelector("#logout").hidden = true;
  }
}

document
  .querySelector("#register-form")
  .addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const data = Object.fromEntries(new FormData(form));
    form.elements.password.value = "";
    const res = await apiFetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    result.textContent = `Register: ${res.status}`;
  });

document.querySelector("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  form.elements.password.value = "";
  const res = await apiFetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  result.textContent = `Login: ${res.status}`;
  await refreshSessionState();
});

document
  .querySelector("#incident-form")
  .addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.currentTarget));
    data.occurredAtUtc = new Date(data.occurredAtUtc).toISOString();
    const res = await apiFetch("/api/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    result.textContent = `Create Incident: ${res.status}`;
  });

document.querySelector("#logout").addEventListener("click", async () => {
  const res = await apiFetch("/api/auth/logout", { method: "POST" });
  result.textContent = `Logout: ${res.status}`;
  await refreshSessionState();
});

await refreshSessionState();
