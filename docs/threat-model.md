# Модель загроз та межі огляду — SecureLab (ЛР № 6)

## 1. Контекст і параметри огляду
- **Предметна область (Baseline):** 2-A (корпоративний трекер інцидентів інформаційної безпеки, основний ресурс — `Incident`).
- **Рівень виконання:** Добрий («Добре»).
- **Початковий стан:** тег `v0.5.0`, гілка `lab/6-hardening-review`, review-start commit: `<ВСТАВТЕ_ВАШ_REVIEW_START_HASH>`.
- **Середовище:** локальний стенд розробки та production-like профіль (`http://localhost:5080`), PostgreSQL 16 у Docker Compose (`127.0.0.1:54329`), .NET 10 SDK (`10.0.*`).

## 2. Елементи моделі загроз

| Елемент | Визначення у межах проєкту SecureLab |
| :--- | :--- |
| **Версія та середовище** | `review-start: <HASH>`; профілі `Development` та `Production` (`--no-launch-profile`); ізольована локальна БД зі штучними обліковими записами (`alice`, `bob`, `morgan`). |
| **Компоненти в межах огляду** | Браузерний клієнт (Vanilla JS: `index.html`, `auth-lab.html`, `browser-lab.html`, `csrf.js`), ASP.NET Core Minimal API (`SecureLab.Api`), база даних PostgreSQL (`infra/compose.yaml`), конфігураційні файли, NuGet-пакети, консольні журнали (`ILogger`). |
| **Активи (Assets)** | Облікові дані та хеші паролів (`AspNetUsers`), сесійні та antiforgery cookies, цілісність та власність записів `Incident` (`OwnerUserId`), привілейовані переходи `Incident.Status`, записи аудиту (`AuditEvent`), секрети конфігурації. |
| **Суб'єкти (Subjects)** | `Anonymous` (неавтентифікований відвідувач), `Reporter` (`alice`, `bob` — робота з власними інцидентами), `Analyst` (`morgan` — тріаж та зміна статусів інцидентів), `Administrator`, локальний розробник/аудитор. |
| **Точки входу (Entry points)** | HTTP-маршрути читання (`GET /api/incidents`, `GET /api/incidents/{id}`, `GET /api/incidents/search`), маршрути автентифікації (`POST /api/auth/login`, `register`, `logout`, `GET /api/me`, `GET /api/antiforgery/token`), маршрути мутації (`POST /api/incidents`, `PUT /api/incidents/{id}`, `POST /api/incidents/{id}/triage`, `DELETE /api/incidents/{id}`), DOM-клієнт, завантаження конфігурації та NuGet restore. |
| **Межі довіри (Trust boundaries)** | 1) `Browser <-> API` (недовірений ввід, автоматичне додавання cookie браузером); 2) `API <-> PostgreSQL` (параметризація запитів та ізоляція підключення); 3) `Repository/NuGet <-> Build` (відсутність секретів у Git, цілісність lock-файлів); 4) `Environment <-> API Startup` (відокремлення Production від Development). |
| **Наявні захисні механізми (Controls)** | Валідація DTO (`ValidationProblemDetails`), ASP.NET Core Identity (cookie auth, `HttpOnly`, `SameSite=Lax`), перевірка власності та ролей (`IncidentAuthorization`), параметризовані запити EF Core, безпечний DOM-рендеринг (`textContent`), точний CORS allowlist, стандартний Antiforgery (`IAntiforgery` + `X-CSRF-TOKEN`), Rate Limiting (`login` та `search`), безпечний `ExceptionHandlerMiddleware` з `traceId`, захисні заголовки (`nosniff`, `no-referrer`). |
| **Явні виключення (Exclusions)** | Не виконувався зовнішній тест на проникнення; реальне TLS-термінування та HSTS на публічному домені поза loopback не тестувалися; розподілений стан у Redis не входить до обраного доброго рівня; повна криміналістична перевірка віддалених клонів Git поза локальним репозиторієм не проводилась. |

## 3. Схема меж довіри

```text
[ Browser Client (Untrusted Input, DOM, Automatic Auth/Antiforgery Cookies) ]
        │
        │  Межа довіри 1: HTTP/JSON + Cookie + X-CSRF-TOKEN Header
        ▼
[ ASP.NET Core API (Rate Limiting, AuthN, AuthZ, AntiforgeryFilter, DTO Validation, Audit/Error Logging) ]
        │
        │  Межа довіри 2: EF Core Parameterized Queries / Connection String (127.0.0.1:54329)
        ▼
[ PostgreSQL Database (Incidents, Identity Tables) ]

[ Git Repository + NuGet Sources ] ──(Межа довіри 3: Locked Restore & Audit)──► [ Build Pipeline ]
[ OS Environment Variables ]       ──(Межа довіри 4: Startup Configuration)───► [ API Host (Dev / Prod) ]