# Звіт до лабораторної роботи № 2

## 1. Ідентифікація стану

- **Дисципліна:** «Прикладні технології програмування в інформаційній безпеці»
- **Лабораторна робота:** № 2. Контракт API, серверна валідація та захист від SQL injection
- **Предметний контракт (baseline):** 2-A «Трекер інцидентів» (`docs/variant-02-a.md`)
- **Базовий стан входу:** власний тег `v0.1.0` + навчальний пакет `lab-02-start-v1`
- **Робоча гілка:** `lab/2-input-sqli`
- **Vulnerable commit hash (стан «до»):** `<ВСТАВТЕ_ХЕШ_VULNERABLE_COMMIT>`
- **Fixed commit hash (стан «після»):** `<ВСТАВТЕ_ХЕШ_FIXED_COMMIT>`
- **Підсумковий тег:** `v0.2.0` (вказує на fixed commit)
- **Перевірка запуску стенда:** Контейнер PostgreSQL (`infra/compose.yaml`) у статусі `Healthy`, застосовано `--reset-database` (у БД наявні 5 штучних інцидентів: `Low = 3`, `Medium = 1`, `High = 1`), збірка та тести у конфігурації `Release` проходять успішно.

---

## 2. Межа контракту та маршрути обробки даних

### Таблиця зовнішнього контракту `POST /api/incidents` (Baseline 2-A)

| Категорія | Поля | Рішення сервера |
| :--- | :--- | :--- |
| **Клієнт надсилає (Request DTO)** | `title`, `description`, `severity`, `occurredAtUtc` | Приймаються виключно через `CreateIncidentRequest`, нормалізуються (`Trim()`) та проходять серверну валідацію до звернення до БД. |
| **Сервер визначає (Server-managed)** | `Id`, `OwnerUserId`, `Status`, `CreatedAtUtc`, `UpdatedAtUtc` | Відсутні у вхідному DTO (захист від overposting / mass-assignment). Встановлюються сервером: `Id = Guid.NewGuid()`, `OwnerUserId = DbSeeder.AliceId` (фіксований контекст до ЛР 3), `Status = IncidentStatus.New`, часи — поточний UTC-час сервера. |
| **API повертає після створення (Response DTO)** | `id`, `title`, `severity`, `status`, `occurredAtUtc`, `createdAtUtc`, `updatedAtUtc` | Формується окремий контракт `CreatedIncidentResponse` зі статусом `201 Created`. Сутність `Incident` напряму не серіалізується. |

### Контрольна точка CP-01: Перевірений контракт створення
- **Маршрут обробки:** `HTTP JSON -> CreateIncidentRequest -> Server-Side Validation (Required, Length, Date, Enum, Cross-Field) -> Duplicate Check (AnyAsync) -> Incident Entity -> PostgreSQL -> CreatedIncidentResponse (201) / Problem Details (400, 409)`.
- **Чому потрібні і `Enum.TryParse`, і `Enum.IsDefined`:** Сам по собі `Enum.TryParse<IncidentSeverity>("7", true, out var severity)` успішно перетворює числовий рядок `"7"` на неіснуюче значення `(IncidentSeverity)7`. Додаткова перевірка `Enum.IsDefined(severity)` гарантує, що значення належить виключно до оголошеного набору `Low, Medium, High, Critical`, і відхиляє `"7"` зі статусом `400 Bad Request`.
- **Чому `<select>` у браузері не замінює серверну перевірку:** Браузер перебуває під повним контролем клієнта; будь-який HTTP-клієнт (`curl`, `.http`-файл, скрипт) надсилає запити напряму до API в обхід HTML/JS-обмежень.

---

## 3. Таблиця спостереження вразливого стану (CP-02)

| Поле | Фактичний запис |
| :--- | :--- |
| **Передумови** | Середовище `Development`, запущений контейнер PostgreSQL, виконано `--reset-database`, активний `vulnerable commit`. |
| **Точка складання SQL (Root Cause)** | Файл `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`, метод `MapLab02Endpoints`: рядки 14–18 (`switch` для `sortBy` із гілкою `_ => sortBy`) та рядки 19–21 (конкатенація рядків `q` і `order` у змінну `sql` із подальшим викликом `db.Incidents.FromSqlRaw(sql)`). |
| **Дія (Нормальний пошук)** | `GET /api/incidents/search?q=USB` — повертає `200 OK` та 1 запис (`"Підозрілий USB-носій у лабораторії"`). |
| **Дія (Контрольний read-only тест S-01)** | `GET /api/incidents/search?q=zz-no-match'%20OR%20TRUE%20--` (тест у `tests/http/lab-02-search.http`). |
| **Очікування без дефекту** | Пошук за відсутнім підрядком має повернути `200 OK` і порожній масив `[]` (0 записів), як і для `q=zz-no-match`. |
| **Фактичне спостереження (до fix)** | Сервер повернув `200 OK` та всі **5 штучних записів** із таблиці `incidents` (включно із записами Alice та Bob, які не містять підрядка). На запиті з легітимним апострофом `q=комп'ютерного` сервер повернув `500 Internal Server Error`. |
| **Пояснення** | Символ апострофа `'` достроково закрив строковий літерал у шаблоні `ILIKE '%...%'`, ключові слова `OR TRUE` змінили логічну структуру предикату `WHERE` на тотожно істинну, а послідовність `--` закоментувала залишок SQL-команди. |

---

## 4. Механізм виправлення (CP-03)

1. **Усунення конкатенації та параметризація (`q`):** Замість передавати в PostgreSQL SQL-текст, до якого вже приєднано `q` через `FromSqlRaw`, пошук переписано на LINQ із використанням `EF.Functions.ILike(incident.Title, pattern, @"\")`. EF Core передає значення `pattern` як окремий параметр SQL (`@p0`), тому СУБД ніколи не інтерпретує вміст параметра як частину структури команди.
2. **Екранування метасимволів `ILIKE`:** Додано метод `EscapeLikePattern`, який екранує символи `\`, `%` та `_`. Завдяки цьому пошук працює як точний пошук буквального підрядка (literal substring), а запит `?q=%25` не повертає всі записи таблиці.
3. **Серверний allowlist для `sortBy`:** Значення `sortBy` перевіряється за білим списком дозволених логічних назв: `createdAtUtc` (за замовчуванням для порожнього або відсутнього параметра), `severity`, `status`. Будь-яке інше значення негайно відхиляється зі статусом `400 Bad Request` і ключем помилки `sortBy` до звернення до БД. Оскільки enum-властивості зберігаються у БД як рядки, реалізовано явне предметне ранжування:
   - Для `severity`: `Critical` -> `High` -> `Medium` -> `Low`.
   - Для `status`: `New` -> `Triaged` -> `InProgress` -> `Resolved` -> `Closed`.

---

## 5. Матриця результатів перевірок (DEL-02)

| ID | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T-01** | Коректне створення | Відновлений seed, унікальний `title`, валідний DTO | `POST /api/incidents` | `201 Created`, `CreatedIncidentResponse` без зайвих полів | Отримано `201 Created`, повернено DTO зі `status: "New"` без внутрішніх полів власника | Автотест `Create_ValidAndDuplicateActiveTitle_Returns201Then409`, `.http` |
| **T-02** | Некоректний DTO | Відновлений seed | `POST /api/incidents` із порожнім `title`, майбутньою датою або `severity: "7"` | `400 Bad Request`, `application/problem+json` | Отримано `400 Bad Request` із безпечним `ValidationProblemDetails` та ключами відповідних полів | Автотест `Create_InvalidSeverity7_AndCrossFieldBoundaries_ReturnExpectedStatuses`, `.http` |
| **T-03** | Предметний конфлікт | Існує активний інцидент (`New`, `Triaged`, `InProgress`, `Resolved`) з тим самим після `Trim()` `title` у тому ж регістрі | Повторний `POST /api/incidents` із тим самим `title` | `409 Conflict` у форматі Problem Details | Отримано `409 Conflict` (`application/problem+json`) із безпечним поясненням конфлікту | Автотест `Create_ValidAndDuplicateActiveTitle_Returns201Then409`, `.http` |
| **S-01** | SQLi до fix | `vulnerable commit`, локальний seed | `GET /api/incidents/search?q=zz-no-match'%20OR%20TRUE%20--` | Небажано розширена вибірка | Отримано `200 OK` та всі 5 штучних записів таблиці замість 0 | Зафіксовано на `vulnerable commit`, табл. CP-02 |
| **S-02** | Retest SQLi | `fixed commit`, той самий seed | Повтор того самого контрольного запиту | Порожній результат за контрактом | Отримано `200 OK` та порожній масив `[]` (0 записів); структура запиту не змінилася | Автотест `Search_ControlledSqliAndWildcards_DoNotExpandResults`, `.http` |
| **T-04** | Позитивна регресія | `fixed commit` | Пошук `q=USB`, `q=комп'ютерного` (`U+0027`) та `q=%25` | Коректні записи, без `500` | Отримано `200 OK`: для `USB` — 1 запис, для `комп'ютерного` — 1 запис, для `%25` — 0 записів | Автотест `Search_ReturnsUsbSeed_AndHandlesApostrophe` |
| **T-05** | Невідоме сортування | `fixed commit` | `GET /api/incidents/search?q=USB&sortBy=unknownColumn` | `400 Bad Request` із ключем `sortBy` | Отримано `400 Bad Request` (`application/problem+json`) із помилкою у полі `sortBy` | Автотест `Search_DefaultAndUnknownSortBy_BehavesAccordingToAllowlist` |
| **T-06** | Ресурс не знайдено | Baseline endpoint | `GET /api/incidents/99999999-9999-9999-9999-999999999999` | `404 Not Found` у Problem Details | Отримано `404 Not Found` (`application/problem+json`) без внутрішніх деталей | Автотест `GetDetails_ForUnknownId_ReturnsProblemDetails404` |
| **T-09** | Cross-field перевірка 2-A | Унікальні `title`, `severity: "High"` | Два `POST /api/incidents`: з 39 та з 40 символами `description` після `Trim()` | Перший — `400` (`description`), другий — `201 Created` | Запит із 39 символами відхилено з `400` (ключ `description`); запит із 40 символами прийнято з `201 Created` | Автотест `Create_InvalidSeverity7_AndCrossFieldBoundaries_ReturnExpectedStatuses` |
| **T-10** | Додаткова нетривіальна предметна перевірка | Правило: `occurredAtUtc` не може бути старішим за 365 днів від поточного UTC-часу | Два `POST`: із датою `-400` днів та з поточною датою | Перший — `400` (`occurredAtUtc`), другий — `201 Created` | Запит із застарілою датою відхилено з `400 Bad Request`, контрольний допустимий запит успішний (`201`) | Автотест `Create_StaleOccurredAtUtc_Returns400_AndMassAssignmentIsIgnored` |
| **A-01** | Огляд data-access points | `fixed commit` | Code search за `FromSqlRaw`, `ExecuteSqlRaw`, `$"SELECT`, `query`, `ORDER BY` | Для кожної точки доступу вказано категорію та висновок | Охоплено всі точки доступу до даних у проєкті; небезпечних конкатенацій не залишилося | Таблиця огляду A-01 нижче |
| **A-02** | Захист від Mass-Assignment / другий дефект | `fixed commit` | Надсилання `ownerUserId` та `status: "Closed"` у JSON до `POST /api/incidents` + усунення ін'єкції в `ORDER BY` (`sortBy`) | Зайві поля ігноруються; `sortBy` обмежено allowlist | Створений запис отримує `status: "New"` та власника Alice; довільний `sortBy` блокується з `400` | Автотест `Create_StaleOccurredAtUtc_Returns400_AndMassAssignmentIsIgnored`, diff |

---

### Таблиця огляду всіх точок доступу до даних (Артефакт A-01)

| Файл та метод | Операція / Конструкція | Категорія | Висновок щодо безпеки |
| :--- | :--- | :--- | :--- |
| `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs` (`MapGet("/api/incidents/search")`) | LINQ `Where` з `EF.Functions.ILike(..., pattern, @"\")` та `switch` allowlist для `OrderBy` | Параметризований LINQ + серверний allowlist | **Виправлено в ЛР 2, безпечно.** Недовірені дані передаються параметром, структура обирається з allowlist. |
| `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs` (`MapPost("/api/incidents")`) | LINQ `AnyAsync(i => i.Title == trimmedTitle && i.Status != IncidentStatus.Closed)` та `db.Incidents.Add` | Параметризований LINQ / EF Core Change Tracking | **Безпечно.** Значення передаються через параметри EF Core. |
| `src/SecureLab.Api/Application/Incidents/IncidentQueries.cs` (`GetListAsync`) | LINQ `AsNoTracking()`, `Where` за статусом, `OrderByDescending(i => i.CreatedAtUtc)` | Параметризований LINQ | **Безпечно.** Фільтрація використовує типізований enum `IncidentStatus`. |
| `src/SecureLab.Api/Application/Incidents/IncidentQueries.cs` (`GetDetailsAsync`) | LINQ `Where(i => i.Id == id)`, `SingleOrDefaultAsync` | Параметризований LINQ | **Безпечно.** Параметр `id` додатково обмежений маршрутом `{id:guid}`. |
| `src/SecureLab.Api/Application/Incidents/IncidentQueries.cs` (`GetSeveritySummaryAsync`) | LINQ `GroupBy(i => i.Severity)`, `Select(g => new { g.Key, Count = g.Count() })` | Параметризований статичний LINQ | **Безпечно.** Зовнішній користувацький ввід не використовується. |
| `src/SecureLab.Api/Data/DatabaseBootstrap.cs`, `DbSeeder.cs`, `Lab02Seed.cs` | Ініціалізація схеми та початкових навчальних даних (`EnsureCreatedAsync`, `AddRange`) | Trusted static data | **Безпечно.** Використовуються лише фіксовані константи коду в локальному середовищі. |

---

## 6. Security-сценарій

1. **Контекст і гіпотеза:** Локальний ендпоінт `GET /api/incidents/search` отримує недовірені параметри `q` та `sortBy` із рядка запиту (query string). Існував ризик того, що ці значення напряму з'єднуються з текстом SQL-команди та змінюють її синтаксичну структуру.
2. **Стан «до»:** На `vulnerable commit` у файлі `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs` (метод `MapLab02Endpoints`, рядки 14–21) значення `q` та `sortBy` конкатенувалися в рядок `sql` через оператор `+` і передавалися у `db.Incidents.FromSqlRaw(sql)`.
3. **Мінімальний PoC:** Використано локальний read-only сценарій `S-01` із файлу `tests/http/lab-02-search.http` та автотесту `SearchMechanicsTests` без руйнівних дій чи звернень поза межі локальної БД.
4. **Спостереження:** Під час виконання контрольного сценарію на `vulnerable commit` замість 0 записів сервер повернув `200 OK` та всі 5 записів таблиці `incidents`. Водночас легітимний пошуковий запит зі словом із апострофом (`комп'ютерного`) призводив до помилки `500 Internal Server Error`.
5. **Першопричина:** Змішування недовірених даних користувача (`q` для фільтрації та `sortBy` для `ORDER BY`) зі структурою SQL-команди до її передачі в СУБД PostgreSQL. Фільтрація окремих символів (наприклад, видалення апострофа або слова `OR`) не усуває першопричину, оскільки ламає легітимні дані українською мовою та не розділяє код і дані.
6. **Виправлення:** Виклик `FromSqlRaw` повністю замінено на параметризований LINQ-запит із `EF.Functions.ILike` та явним екрануванням метасимволів шаблону (`\`, `%`, `_`). Для вибору структури сортування `sortBy` реалізовано суворий серверний allowlist (`createdAtUtc`, `severity`, `status`) із явним ранжуванням значень. Для створення інциденту реалізовано повну серверну валідацію контракту `CreateIncidentRequest`.
7. **Retest і позитивна регресія:** Після виправлення (на `fixed commit`) той самий контрольний read-only сценарій повертає `200 OK` та порожній масив `[]` (`S-02`). Штатний пошук (`USB`), пошук слова з апострофом (`комп'ютерного`) та буквальний пошук символу `%` працюють коректно без помилки `500` (`T-04`). Усі 10 інтеграційних тестів у `SecureLab.Api.Tests` проходять успішно.
8. **Залишковий ризик:** Впроваджена валідація контракту та параметризація SQL-запитів не замінюють повноцінну автентифікацію користувача (наразі `OwnerUserId` призначається з фіксованого демо-контексту Alice — це буде усунено в ЛР 3 через verified principal), перевірку прав доступу до чужих ресурсів (авторизація в ЛР 4), захист клієнтського рендерингу від XSS (ЛР 5) та обмеження частоти запитів (rate limiting у ЛР 6).