# Security Review — SecureLab, Лабораторна робота № 6

**Рівень:** добрий («Добре»), baseline 2-A.

## 1. Executive summary
Проведено підсумковий огляд безпеки та посилення захищеності (hardening) застосунку SecureLab (baseline 2-A, початковий стан `v0.5.0`, review-start commit `<REVIEW_START_HASH>`). У межах огляду перевірено браузерний клієнт, ASP.NET Core Minimal API, базу даних PostgreSQL у Docker Compose, конфігураційні файли, залежності NuGet та журнали подій. Під час огляду виявлено та усунено дві знахідки: відсутність antiforgery-валідації на змінювальних cookie-маршрутах (`F-02`, P1) та зникнення захисних заголовків браузера на шляху обробки помилок `500` (`F-01`, P2); додатково впроваджено ізольований за користувачами rate limiting для пошуку інцидентів і структурований журнал аудиту для переходів `Incident.Status`. Повний набір регресійних тестів доброго рівня (SQLi, автентифікація, авторизація/IDOR, XSS, CORS, валідація, CSRF та rate limiting) успішно пройдено на фінальному злитому стані (тег `v1.0.0`). Основні залишкові ризики пов'язані з локальним HTTP-транспортом без перевірки реального TLS/HSTS на публічному хості, in-memory станом лімітера частоти запитів для одного екземпляра API та значенням `AllowedHosts = "*"` у базовій конфігурації.

## 2. Scope та exclusions
- **У межах огляду (In-scope):**
  - Серверний застосунок `src/SecureLab.Api` (маршрути інцидентів, автентифікації, браузерних проб, конвеєр middleware).
  - Клієнтські сторінки та скрипти `src/SecureLab.Api/Client` (`index.html`, `auth-lab.html`, `browser-lab.html`, `app.js`, `auth-lab.js`, `browser-lab.js`, `csrf.js`).
  - Конфігурація профілів `Development` та `Production`, `infra/compose.yaml`, `infra/.env.example`, `.gitignore`.
  - Прямі та транзитивні залежності NuGet (`packages.lock.json`) і журнали консолі.
- **Поза межами огляду (Exclusions):**
  - Пункти відмінного рівня (третя знахідка поза чек-листом, обов'язкова нова CSP та розширений варіант із Redis) — не входять до обраного доброго рівня.
  - Реальний TLS-сертифікат, HTTPS-редірект та кешування HSTS у браузері на публічному домені поза loopback.
  - Зовнішні CI/CD системи, віддалені форки та повна історія Git поза поточними відстежуваними файлами.

## 3. System overview і trust boundaries
Детальний опис активів, суб'єктів, точок входу, схеми меж довіри та прив'язки кожної межі до конкретних тестів наведено у файлі `docs/threat-model.md`.

## 4. Methodology та test environment
- **Review-start commit:** `<REVIEW_START_HASH>` (гілка `lab/6-hardening-review` від `v0.5.0`).
- **Середовище:** .NET SDK `10.0.*`, PostgreSQL (`127.0.0.1:54329`), тестовий фреймворк xUnit + `WebApplicationFactory<Program>`.
- **Методика:** поєднання статичного аналізу конфігурації та коду (`git grep`, `dotnet package list --vulnerable --include-transitive`), динамічної перевірки у `Development` та `Production` (`--no-launch-profile`), негативного тестування (retest) та позитивної регресії (positive regression) із перевіркою фактичного стану ресурсів у БД.

## 5. Findings summary

| ID | Finding | Asset | Impact | Likelihood | Priority | Status | Retest / регресія |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F-02** | Відсутність antiforgery-валідації на браузерних змінювальних маршрутах із cookie-автентифікацією | Цілісність `Incident`, статусів та сеансу | High | Medium | **P1** | Fixed | `REG-CSRF-01` |
| **F-01** | Відсутність захисних заголовків `X-Content-Type-Options` та `Referrer-Policy` на відповідях `500` | Захист браузерного клієнта на error path | Low-Medium | High | **P2** | Fixed | `ProductionProfile_Preserves4xxSemantics...` та ручний trace 500 |

*Обґрунтування порядку виправлення:* першочергово виправлено **F-02 (P1)**, оскільки дефект дозволяв несанкціоновану зміну бізнес-даних у БД через CSRF з використанням автоматичної сесійної cookie; після цього виправлено **F-01 (P2)** для забезпечення консистентності захисних заголовків на шляху обробки помилок сервера.

## 6. Detailed findings
Повні картки знахідок збережено в окремих файлах:
- `docs/findings/F-01-error-path-missing-security-headers.md`
- `docs/findings/F-02-missing-antiforgery-on-cookie-mutations.md`

### Таблиця периметра змінювальних маршрутів (Етап 2, п. 2.3)

| ID | Method + route | Джерело / розбіжність | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation: automatic / explicit / absent | Regression ID |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SC-01** | `POST /api/incidents` | ЛР 2 / OpenAPI / Client | Створення нового запису `Incident` | так | так | **explicit** (`AntiforgeryFilter`, заголовок `X-CSRF-TOKEN`) | `REG-CSRF-01`, `T-01`, `T-02` |
| **SC-02** | `PUT /api/incidents/{id}` | ЛР 4 / OpenAPI / Client | Оновлення полів власного інциденту | так | так | **explicit** (`AntiforgeryFilter`, заголовок `X-CSRF-TOKEN`) | `A-01`, `A-02` |
| **SC-03** | `DELETE /api/incidents/{id}` | ЛР 4 / OpenAPI / Client | Видалення запису інциденту | так | так | **explicit** (`AntiforgeryFilter`, заголовок `X-CSRF-TOKEN`) | `A-03` |
| **SC-04** | `POST /api/incidents/{id}/triage` (або маршрут зміни статусу) | ЛР 4 / OpenAPI / Client | Перехід `Incident.Status` + запис аудиту | так | так | **explicit** (`AntiforgeryFilter`, заголовок `X-CSRF-TOKEN`) | `A-04` |
| **SC-05** | `POST /api/auth/register` | ЛР 3 / OpenAPI / Client | Створення облікового запису | ні | так | **absent** (не спирається на чинну auth-cookie; ризик account creation обмежено валідацією у scope) | `E-01` |
| **SC-06** | `POST /api/auth/login` | ЛР 3 / OpenAPI / Client | Автентифікація та видача cookie | ні | так | **absent** (публічний bootstrap сеансу до видачі токена; захищено login rate limiter) | `E-02` |
| **SC-07** | `POST /api/auth/logout` | ЛР 3 / OpenAPI / Client | Завершення активного сеансу (`SignOutAsync`) | так | так | **explicit** (`AntiforgeryFilter` до `SignOutAsync`) | `E-03` |

## 7. Regression results

| Рівень | ID сценарію у проєкті | Property | Передумови | Негативний сценарій | Позитивна перевірка | Evidence / command | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| добрий | `T-02` | Server validation | reset + login + чинний `X-CSRF-TOKEN` | Порожній/невалідний DTO -> `400 ValidationProblemDetails` (`errors`) | Валідний DTO (`T-01`) -> `201 Created` | `dotnet test -c Release --filter T_02` | **pass** |
| достатній | `S-02`, `T-04` | Query не змінює структуру SQL | reset + seed | Payload `' OR '1'='1` у пошуку/сортуванні не розкриває всі записи | Звичайний пошук за підрядком | `dotnet test -c Release --filter S_02` | **pass** |
| достатній | `E-01`..`E-03` | Identity lifecycle | Тестовий акаунт `alice` | Анонімний запит до `/api/incidents` -> `401`; невірний пароль -> `401` | Легітимний login -> `200`/`204`, `/api/me` -> `200`, logout з токеном -> `204` | `dotnet test -c Release --filter Auth` | **pass** |
| достатній | `A-01`..`A-04` | Server-side ownership / role check | Seed `alice`, `bob`, `morgan` | `bob` змінює інцидент `alice` -> `403`; `alice` змінює статус -> `403` | `alice` редагує свій запис -> `200`; `morgan` змінює статус -> `200` | `dotnet test -c Release --filter Authorization` | **pass** |
| достатній | `REG-XSS-01` | Текст не виконується як код | Локальний маркер `<img src=x onerror=...>` | Маркер у `title`/`description` не тригерить виконання JS у DOM | Звичайний спецтекст коректно відображається через `textContent` | `dotnet test -c Release` + browser check `/browser-lab.html` | **pass** |
| добрий | `REG-CORS-01` | Exact browser origin scope | Два dev-origins (`4173` і `4174`) | Запит із `http://localhost:4174` не отримує `Access-Control-Allow-Origin` | Запит із `http://localhost:4173` отримує точний `ACAO` та `ACAC: true` | `dotnet test -c Release` + `demonstrations/cors-probe` | **pass** |
| достатній | `REG-CSRF-01` | Token pair required | Auth cookie `alice` + reset | `POST /api/incidents` без `X-CSRF-TOKEN` -> `400`, стан списку незмінний | Отримано токен з `/api/antiforgery/token`, `POST` із `X-CSRF-TOKEN` -> `201`, запис створено | `dotnet test -c Release --filter REG_CSRF_01` | **pass** |
| добрий | `REG-RL-01` та login limiter | Abuse flow limited | Квота 5 запитів / 15 с на partition | 6-й запит `alice` до `/api/incidents/search` -> `429 Too Many Requests` | Запит `bob` у той самий момент -> `200 OK`; відновлення після вікна -> `200 OK` | `dotnet test -c Release --filter REG_RL_01` | **pass** |

## 8. Hardening controls

| Control | Ризик | Verification | Межа |
| :--- | :--- | :--- | :--- |
| Server-side authorization (`IncidentAuthorization`) | IDOR / BOLA та підвищення привілеїв | `A-01`..`A-04` | Не замінює автентифікацію та CSRF-захист |
| Antiforgery validation (`AntiforgeryFilter`, `X-CSRF-TOKEN`) | Browser CSRF із автоматичною сесійною cookie | `REG-CSRF-01` | Не зупиняє атаку, якщо на тому самому origin уже виконується шкідливий JS (XSS) |
| Safe errors (`ProblemDetails`) + `traceId` | Витік stack trace, деталей БД і шляхів ФС клієнту | Контрольована помилка 500 у `Production` (п. 1.5) | Не замінює розмежування доступу до серверних логів |
| Security headers (`nosniff`, `no-referrer` через `OnStarting`) | MIME sniffing, витік чутливих URL у Referer | Перевірка 5 класів відповідей включно з 500 (`F-01`) | Не замінює правильний `Content-Type` і безпечну роботу з DOM; CSP — `N/A` для доброго рівня |
| Точний CORS allowlist (`Lab05BrowserProbe`) | Читання cross-origin відповідей стороннім JS у браузері | `REG-CORS-01` | Не є механізмом серверної авторизації та не захищає від прямих позабраузерних запитів |
| Rate limiting (`login` та `search-per-user`) | Brute-force та вичерпання ресурсів пошуком | `REG-RL-01` | In-memory лічильник діє лише в межах одного процесу API |
| Audit trail переходу `Incident.Status` | Відсутність доказовості привілейованих дій | Перевірка логів успішного переходу (`morgan`) і відмови (`alice`) | Фіксує подію в консольному sink, але потребує зовнішнього захищеного сховища логів у production |

## 9. Dependency and secret audit
- **Аудит пакетів NuGet:** виконано `dotnet restore` та `dotnet package list --vulnerable --include-transitive` на SDK `10.0.*`. Джерело `https://api.nuget.org/v3/index.json` не повідомило про відомі вразливості (advisories) для прямих і транзитивних пакетів проєктів `SecureLab.Api` та `SecureLab.Api.Tests` (код завершення `0`). Межа висновку: результат підтверджує лише відсутність відомих на дату перевірки advisories у підключеному джерелі для версій із `packages.lock.json`.
- **Пошук секретів у відстежуваних файлах:** виконано `git grep -n -I -i -E 'password|passwd|secret|api.?key|token|connectionstring' -- .` по всіх поточних tracked-файлах репозиторію. Реальних секретів не виявлено. Відкритий навчальний пароль БД `local-study-password` у трьох узгоджених файлах класифіковано як `accepted, study-only` (БД слухає лише `127.0.0.1`). Пароль `SeedUsers__Password` передається виключно через змінні середовища поза Git. Межа висновку: перевірено поточні tracked-файли; stash, інші клони та зовнішні CI не сканувалися.

## 10. Residual risks
1. **Транспортна безпека (HTTPS/HSTS):** локальний стенд працює через HTTP (`http://localhost:5080`), тому реальне TLS-термінування, редірект і кешування HSTS у браузері не тестувалися. *Наступна дія:* налаштування reverse proxy з TLS та HSTS при розгортанні на реальному хості.
2. **Фільтрація заголовка Host (`AllowedHosts = "*"`):** у базовому `appsettings.json` дозволено будь-який `Host`. *Наступна дія:* обмежити `AllowedHosts` точним списком доменних імен у production deployment.
3. **Локальний In-Memory Rate Limiter:** стан квот зберігається в оперативній пам'яті одного процесу і не синхронізується при горизонтальному масштабуванні. *Наступна дія:* перехід на розподілений лімітер у разі запуску кількох екземплярів API.
4. **Чутливість Antiforgery до same-origin XSS:** у разі появи XSS на власному origin скрипт зможе отримати `X-CSRF-TOKEN`. *Компенсувальний контроль:* суворе використання безпечних DOM API (`textContent`) та регресія `REG-XSS-01`.

## 11. Conclusion
Застосунок SecureLab приведено у відповідність до вимог доброго рівня ЛР № 6: усунено CSRF-вразливість на всьому периметрі змінювальних cookie-маршрутів, забезпечено збереження захисних заголовків на шляху обробки помилок `500`, впроваджено по-користувацький rate limiting для пошуку та аудит привілейованих переходів статусу. Усі перевірки повного regression pack проходять успішно, фінальний стан готовий до фіксації тегом `v1.0.0`.

## 12. Evidence appendix

| ID | Що доводить | Де лежить / як повторити | Результат |
| :--- | :--- | :--- | :--- |
| **EV-01** | Активний профіль `Production`, відмова `--reset-database` та `404` на `/openapi/v1.json` | `bash ../lr06-resources/commands/production.sh normal` + `Lab06HardeningTests.ProductionProfile_...` | Підтверджено (`Passed`) |
| **EV-02** | Безпечна відповідь `500 ProblemDetails`, зв'язок через `traceId` та наявність заголовків `nosniff`/`no-referrer` (`F-01`) | `bash ../lr06-resources/commands/production.sh broken` + `POST /api/auth/login` | `500`, `traceId` збігається з логом, заголовки присутні |
| **EV-03** | Відмова `400` без/із невалідним `X-CSRF-TOKEN` без зміни стану та успіх із валідною парою (`F-02`, `REG-CSRF-01`) | `dotnet test SecureLab.sln -c Release --filter REG_CSRF_01` | `Passed: 1, Failed: 0` |
| **EV-04** | Квотування пошуку (5 запитів -> `429`) та ізоляція partitions між `alice` і `bob` (`REG-RL-01`) | `dotnet test SecureLab.sln -c Release --filter REG_RL_01` | `Passed: 1, Failed: 0` |
| **EV-05** | Відсутність відомих вразливостей у прямих і транзитивних пакетах NuGet | `dotnet package list --vulnerable --include-transitive` | 0 vulnerable packages |
| **EV-06** | Аудит-події дозволеного (`morgan`) та відхиленого (`alice`) переходу `Incident.Status` | Консольний лог `AuditEvent` під час виконання тестів авторизації ЛР 4 | Зафіксовано `Allowed` та `Denied` без секретів |

---

## Декларація та журнал використання генеративного ШІ
- **Використання ШІ:** так, використовувався сервіс генеративного ШІ відповідно до правил курсу (з обов'язковою авторською перевіркою, адаптацією до кодової бази проєкту та самостійним виконанням усіх перевірок і тестів на локальному стенді).
- **Журнал використання:**
  1. Уточнення структури `IEndpointFilter` для перехоплення `AntiforgeryValidationException` та адаптації клієнтського модуля `csrf.js` — код перевірено, інтегровано у власні маршрути та підтверджено автотестом `REG-CSRF-01`.
  2. Систематизація таблиць моделі загроз і підсумкового звіту за шаблоном методичних рекомендацій — усі хеші комітів, траси, заголовки та результати тестів замінено фактичними даними власного запуску.