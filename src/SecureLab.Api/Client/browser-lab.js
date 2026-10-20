const id = () => document.querySelector("#incident-id").value.trim();

function renderPlainText(element, text) {
  element.textContent = text ?? "";
  return element;
}

async function load() {
  const response = await fetch(`/api/incidents/${encodeURIComponent(id())}`);
  document.querySelector("#status").textContent = `GET: ${response.status}`;
  if (!response.ok) return;

  const data = await response.json();
  document.querySelector("#title").textContent = data.title ?? "";
  renderPlainText(document.querySelector("#description"), data.description);
  document.querySelector("[name=description]").value = data.description ?? "";

  const commentsBox = document.querySelector("#comments");
  const commentNodes = [];
  for (const item of data.comments ?? []) {
    const commentElement = renderPlainText(
      document.createElement("p"),
      item.text,
    );
    commentNodes.push(commentElement);
  }
  commentsBox.replaceChildren(...commentNodes);
}

document.querySelector("#load").addEventListener("click", load);
document
  .querySelector("#create-form")
  .addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget.elements;
    const response = await fetch("/api/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: form.title.value,
        description: form.description.value,
        severity: "Medium",
        occurredAtUtc: new Date().toISOString(),
      }),
    });
    document.querySelector("#status").textContent = `POST: ${response.status}`;
    if (!response.ok) return;
    const created = await response.json();
    document.querySelector("#incident-id").value = created.id;
    await load();
  });
