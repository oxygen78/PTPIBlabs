# Звіт до лабораторної роботи № 3

## Відтворення
Обраний рівень/оцінка: Добре; автор/група: [Ваше ПІБ/Група]; baseline 2-A; base tag v0.2.0: [Хеш v0.2.0]; scaffold release/base_commit: lab-03-start-v1 / [Хеш базового коміта scaffold]; гілка: lab/3-authentication; перевірений commit/tag v0.3.0: [Хеш v0.3.0]; ОС/SDK: Windows/macOS / .NET 10.0.100; команди build/tests: `dotnet build -c Release`, `dotnet test -c Release`; фактичний результат: Passed! Failed: 0; спосіб migration/reset і перевірка двох reset: `Reset-Twice.ps1`, обидва запуски успішні (Passed! Failed: 0).

## Власна реалізація і межі
DTO boundary: Клієнт передає лише дозволені поля. Поля `OwnerUserId`, `Role`, `Id` ігноруються, якщо передані.
Звідки /api/me та create беруть id: З `HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)`.
Cookie options і межа HTTP: `HttpOnly=true` (захист від читання JS), `SecurePolicy` (HTTPS в production), `SameSite=Lax` (базовий захист від CSRF).
Фактичні flags: `path=/; samesite=lax; httponly` (локально HTTP) або `secure` при HTTPS.
Строк дії: Стандартний для Identity (сеансова cookie без expires).
Надані однакові login-відмови: 401 Unauthorized без розкриття факту існування акаунту (А-07 успішний).
Обраний duplicate контракт: Повертається 409 Conflict.
Rate partition/window/recovery і події: Ключ — IP-адреса клієнта (RemoteIpAddress). Ліміт 5 запитів на 10 секунд. Відновлення після вікна перевірено. Подія автентифікації логується без паролів та хешів.
CSRF навчальний борг: `SameSite=Lax` відсікає лише частину крос-сайтових запитів; повноцінний захист (Anti-Forgery Tokens) відсутній (до ЛР6).

## Докази

Пояснення:
Маршрут довіри: Клієнт надсилає запит на Login -> Identity перевіряє хеш пароля -> генерує зашифровану Cookie -> браузер надсилає Cookie в наступних запитах -> Authentication Handler розшифровує Cookie і створює `ClaimsPrincipal` -> Endpoint дістає ID з Principal і призначає його власником (OwnerUserId).
Стандартна перевірка пароля: Виконується `UserManager`, хеші використовують унікальну сіль і PBKDF2 (100 000 ітерацій), що захищає від райдужних таблиць.
Чому client UserId не є доказом особи: Дані в body або header можуть бути легко підроблені зловмисником. Довіряти можна лише зашифрованій Cookie, згенерованій сервером.
Endpoint-и перебору акаунтів: `/api/auth/register` (компроміс: віддаємо 409 для покращення UX, але лімітуємо запити). `/api/auth/login` захищений поверненням однакового 401 для всіх помилок.

| ID | Рівень | Передумова/дія | Очікувано | Фактично | Безпечний доказ |
|---|---|---|---|---|---|
| T-01 | достатній | register | safe 201 | 201 Created | Тест пройдено, JSON не містить password/cookie. |
| T-02 | достатній | invalid/duplicate | safe rejection | 400 / 409 Conflict | Тест пройдено, повертається ProblemDetails. |
| T-03 | достатній | модель/схема + Identity verifier | password не відкрито | Стовпець PasswordHash типу text | Вивід `schema.ps1` без SELECT даних. |
| A-01 | достатній | anonymous protected request | 401, no redirect | 401 Unauthorized | Автотест `A01_AnonymousRequest_Returns401` пройшов. |
| A-02 | достатній | login → me | principal user | 200 OK, профіль Alice | Автотест `A02_Login_GetsProfileSuccessfully` пройшов. |
| A-05 | достатній | Bob створює запис із forged owner Alice | новий owner = Bob | OwnerUserId == BobId | Автотест `A04_A05_CreateIncident` пройшов. |
| S-01 | достатній | аналіз credentials boundary | без витоків | Витоків не виявлено | Логи та відповіді не містять паролів. |
| A-03 | добрий | Valid cookie з X-Demo-UserId іншого user | /api/me незмінний | Повертається профіль Alice | Автотест `A03_SpoofedHeader_DoesNotChangeProfile` пройшов. |
| A-04 | добрий | Authenticated create без owner у DTO | owner із principal | OwnerUserId == BobId | Автотест `A04_A05_CreateIncident` пройшов. |
| A-06 | добрий | Logout | 401 після logout | 401 Unauthorized | Автотест `A06_Logout_Returns401OnSubsequentRequests` пройшов. |
| A-07 | добрий | Unknown user і неправильний пароль | однаковий результат | 401 для обох випадків | Автотест `A07_UnknownUser_And_BadPassword` пройшов. |
| Browser flow | добрий | п'ять перевірок етапу 4 | state/profile/create/logout | Працює коректно | Задокументовано в session-state-demo.js |
| Duplicate | добрий | обраний контракт і регресія | послідовний 400/409 | 409 Conflict для дубліката | Опрацьовано у логіці `/register`. |
| Rate limit | добрий | перевищення ліміту, відновлення | 429, відновлення | 429 Too Many Requests | Логування працює без credentials. |