# Карта потоків даних source -> transformations -> sink (ЛР 05)

Виконав: Корбут Данило Андрійович
Обраний рівень виконання: **Добре**
Сценарій: **Спільний сценарій 2-A** (`Incident.Description` та `IncidentComment.Text`)

## 1. Основний потік: `Incident.Description`

| Крок | Де виникає або змінюється значення | Дані / доказ | Статус довіри |
| :--- | :--- | :--- | :--- |
| **Source** | Форма `#create-form` на `/browser-lab.html`, поле `<textarea name="description">` | `event.currentTarget.elements.description.value` | Контрольоване користувачем (Untrusted) |
| **Request** | `fetch("/api/incidents", { method: "POST" })` у `Client/browser-lab.js` | JSON-поле `description` у Request Payload | Контрольоване користувачем (Untrusted) |
| **Server transform** | `Presentation/Endpoints/IncidentEndpoints.cs` -> `CreateIncidentRequest` -> валідація довжини | Мапінг у сутність `Incident.Description` без HTML-екранування | Не стає trusted HTML після серверної валідації довжини |
| **Storage** | Таблиця `Incidents` у PostgreSQL (`SecureLabDbContext`) | Колонка `Description` (збережений рядок маркера) | Збережене значення користувача (Untrusted) |
| **Response** | `GET /api/incidents/{id}` -> `IncidentDetailsResponse.Description` | JSON-поле `description` у Response (200 OK) | Недовірене для відображення браузером як HTML |
| **Client transform** | Функція `load()` у `src/SecureLab.Api/Client/browser-lab.js` | `const data = await response.json();` -> `data.description` | Залежить від способу вставки в DOM |
| **Sink (До)** | `document.querySelector("#description").innerHTML = data.description ?? ""` | Вставка сирого рядка у `innerHTML` елемента `#description` | **Небезпечний (HTML parser context)** — спричиняє Stored/DOM XSS |
| **Sink (Після)** | `renderPlainText(document.querySelector("#description"), data.description)` | Запис через `element.textContent = text ?? ""` | **Безпечний (DOM text node context)** — дані не інтерпретуються як HTML |

## 2. Додатковий потік (рівень «Добре»): `IncidentComment.Text`

| Крок | Де виникає або змінюється значення | Дані / доказ | Статус довіри |
| :--- | :--- | :--- | :--- |
| **Source** | `src/SecureLab.Api/Data/DbSeeder.cs` (`SeedAsync`, константа `Lab05Marker`); у продукті — форма автора коментаря | Поле `Text` коментаря `30000000-0000-0000-0000-000000000005` | Збережене значення користувача (Untrusted) |
| **Request / Seed** | Ініціалізація `dbContext.IncidentComments.AddRange(...)` під час `--reset-database` | Запис коментаря до інциденту `20000000-0000-0000-0000-000000000001` | Збережене значення користувача (Untrusted) |
| **Storage** | Таблиця `IncidentComments` у PostgreSQL | Колонка `Text`, `IsInternal = false` | Збережене значення користувача (Untrusted) |
| **Response** | `GET /api/incidents/20000000-0000-0000-0000-000000000001` -> `IncidentCommentResponse` | Масив `comments[].text` у JSON-відповіді | Недовірене для відображення браузером як HTML |
| **Client transform** | Обхід `for (const item of data.comments ?? [])` у `Client/browser-lab.js` (`load()`) | Читання `item.text` для кожного коментаря | Залежить від способу вставки в DOM |
| **Sink (До)** | Конкатенація `item.text` у `#comments.innerHTML` | Передача рядка коментаря в HTML-парсер браузера | **Небезпечний (HTML parser context)** — спричиняє Stored/DOM XSS |
| **Sink (Після)** | `renderPlainText(document.createElement("p"), item.text)` + `commentsBox.replaceChildren(...)` | Створення `<p>`, запис тексту у `textContent`, заміна вузлів через `replaceChildren` | **Безпечний (DOM text node context)** — розмітку створює код, дані лишаються текстом |