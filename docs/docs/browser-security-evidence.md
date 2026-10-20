# Доказовий комплект безпеки браузера (DEL-01, ЛР 05)

## 1. Стенд і Git-стан (DEL-02)
* **Виконав:** Корбут Данило Андрійович
* **Рівень виконання:** Добре
* **Scaffold Release ID:** `lab-05-start-v1`
* **Base commit (`v0.4.0`):** `<вставте_base_commit_із_.scaffolds/lab-05.json>`
* **Робоча гілка / Підсумковий тег:** `lab/5-browser-xss` -> `main`, тег `v0.5.0`
* **Топологія стенда:**
  * Штатний клієнт та API (same-origin): `http://localhost:5080`
  * Навчальний дозволений CORS probe: `http://localhost:4173` (`py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe`)
  * Контрольний недозволений CORS probe: `http://localhost:4174` (`py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe`)

## 2. Інвентаризація DOM sinks (`src/SecureLab.Api/Client/browser-lab.js`) та Гіпотеза

| Місце в коді | Дані, що потрапляють у sink | Категорія даних | Контекст | Рішення |
| :--- | :--- | :--- | :--- | :--- |
| `#status.textContent` | Статус-код HTTP (`GET: 200`, `POST: 201`) | Server-generated / trusted template | Text node | Безпечно (`textContent`) |
| `#title.textContent` | `data.title` | Збережене значення користувача | Text node | Безпечно (`textContent`) |
| `#description.innerHTML` (до fix) | `data.description` | Збережене значення користувача | HTML parser | **Небезпечно** -> замінити на `renderPlainText` (`textContent`) |
| `#comments.innerHTML` (до fix) | `data.comments[].text` | Збережене значення користувача | HTML parser | **Небезпечно** -> замінити на `createElement("p")` + `renderPlainText` + `replaceChildren` |

**Гіпотеза:**
Значення з поля форми `description` (або `comments[].text` із seed/БД) зберігається в PostgreSQL (`Incidents.Description` / `IncidentComments.Text`), повертається через JSON-відповідь (`description` / `comments[].text`) і передається у sink `innerHTML` як HTML-контекст; тому за наявності HTML-розмітки з обробниками подій (наприклад, `<img src=x onerror="...">`) браузер може інтерпретувати дані не як звичайний текст, а як виконуваний JavaScript-код.

## 3. Finding та результати XSS PoC (До і Після виправлення)

* **Канонічний маркер (`resources/lab05-marker.txt`):**
  `<img src=x onerror="document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker', 'executed')">`
* **Тестові ідентифікатори:**
  * Створений інцидент Alice із маркером в описі: `<вставте_Guid_створеного_інциденту>`
  * Seed-інцидент Alice із маркером у коментарі (`30000000-0000-0000-0000-000000000005`): `20000000-0000-0000-0000-000000000001`
* **Модель Finding:**
  * **Актив:** сеанс автентифікованого користувача у браузері (зокрема привілейованого аналітика `Morgan` з роллю `Analyst`) та доступні йому дані інцидентів.
  * **Передумови:** автентифікований користувач (`Alice`), який має право створити інцидент або залишити коментар.
  * **Першопричина:** передавання недовірених збережених текстових даних (`data.description`, `item.text`) у HTML-парсер браузера через властивість `innerHTML` замість створення текстових вузлів DOM.
  * **Вплив на стенді:** у сеансі автора (`Alice`) та привілейованого глядача (`Morgan`) створюється елемент `<img>` і виконується JS-обробник `onerror`, який змінює атрибут `data-lab05-marker` на `"executed"`. Для неавторизованого `Bob` сервер повертає `403`/`404`, маркер = `null`.
  * **Виправлення:** впроваджено єдиний безпечний helper `renderPlainText(element, text)` на базі `textContent`, `document.createElement("p")` та `replaceChildren()`.
  * **Retest:** збережене в БД та JSON значення не змінилося, але в DOM воно відображається як текстовий вузол; елемент `<img>` не створюється, запит `/x` відсутній, перевірка маркера повертає `null`.
  * **Залишковий ризик:** сторонній UI-пакет `/scalar/v1` у середовищі Development та можлива поява нових клієнтських полів у майбутньому.

## 4. Прогноз та фактичні результати дослідження Origin і CORS

| Browser origin / клієнт і запит | Прогноз: чи дійде до API? | Прогноз: чи прочитає JS? | Фактичний результат після налаштування `Lab05BrowserProbe` |
| :--- | :--- | :--- | :--- |
| Same-origin `:5080` -> `:5080` | Так | Так | `GET 200 OK`, дані читаються, CORS не потрібен |
| Allowed `:4173`, simple `GET /health` | Так | Так (за наявності policy) | `GET 200 OK`, присутній `Access-Control-Allow-Origin: http://localhost:4173`, JS читає JSON |
| Allowed `:4173`, header `X-Lab-Cors-Probe` | Спочатку `OPTIONS`, потім `GET` | Так | `OPTIONS 204` (з `Allow-Origin`, `Allow-Methods: GET`, `Allow-Headers: X-Lab-Cors-Probe`, `Allow-Credentials: true`), далі `GET 200 OK` |
| Disallowed `:4174`, simple `GET /health` | Так | Ні | `GET 200 OK` виконано сервером, але без `Access-Control-*`; браузер блокує читання (`TypeError: Failed to fetch`) |
| Disallowed `:4174`, header `X-Lab-Cors-Probe` | Лише `OPTIONS` | Ні | `OPTIONS 204` без `Access-Control-*`; браузер зупиняє preflight і не надсилає actual `GET` |
| Allowed `:4173`, `credentials: "include"` до `/api/incidents` | Так (із Cookie) | Так | `GET 200 OK` зі списком інцидентів (або `401` без сесії), JS читає відповідь завдяки `Allow-Credentials: true` і точному origin |
| Disallowed `:4174`, `credentials: "include"` до `/api/incidents` | Так (із Cookie) | Ні | Запит дійшов до API разом із Cookie і виконався (`200 OK`), але браузер приховав відповідь від JS |
| Прямий клієнт `curl.exe` (з `Origin: http://localhost:4174`) | Так | Не застосовується | `HTTP/1.1 200 OK`, тіло читається повністю, бо SOP/CORS застосовується лише браузером |

## 5. Інвентаризація ресурсів для Content Security Policy та браузерних заголовків

| Директива / Заголовок | Фактична потреба застосунку | Обране значення | Що обмежує / який ризик зменшує | Чого НЕ замінює |
| :--- | :--- | :--- | :--- | :--- |
| `default-src` (та fallback для `script-src`, `style-src`, `img-src`, `connect-src`) | Усі HTML, JS (`app.js`, `auth-lab.js`, `browser-lab.js`), CSS та `fetch` працюють із `http://localhost:5080` | `'self'` | Блокує завантаження сторонніх скриптів/зображень/стилів і забороняє виконання inline-скриптів та `onerror` (defense in depth) | Безпечний рендеринг DOM (`textContent`), бо без нього розмітка все одно модифікується |
| `frame-ancestors` | Вбудовування у фрейми продуктово не потрібне | `'none'` | Забороняє вбудовування сторінки в `<iframe>`/`<frame>`, усуваючи ризик Clickjacking | Серверну авторизацію та захист від XSS |
| `X-Content-Type-Options` | Сервер віддає чіткі MIME-типи | `nosniff` | Забороняє браузеру MIME sniffing (вгадування типу вмісту за байтами відповіді) | Коректний `Content-Type` та валідацію на сервері |
| `Referrer-Policy` | Переходи між `/`, `/auth-lab.html`, `/browser-lab.html` не потребують передачі `Referer` | `no-referrer` | Запобігає витоку URL сторінки-джерела у заголовку `Referer` під час переходів і запитів | Заборону передавати секрети чи токени в URL |

## 6. Регресійні сценарії (REG-XSS-01 та REG-CORS-01)

### REG-XSS-01 (Відтворювана процедура перевірки захисту від XSS)
* **Передумови:** запущений у Development API на `http://localhost:5080` з `fixed_commit` (`v0.5.0`), виконано `--reset-database`, виконано вхід під `alice` та в окремому вікні під `morgan`.
* **Вхід:** канонічний маркер із `resources/lab05-marker.txt`:
  `<img src=x onerror="document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker', 'executed')">`
* **Кроки:**
  1. На `/browser-lab.html` перевірити в Console `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")` -> `null`.
  2. Створити новий інцидент із маркером у полі «Опис нового інциденту» («Створити й прочитати») та відкрити його в сеансі `morgan`.
  3. Відкрити seed-інцидент `20000000-0000-0000-0000-000000000001` (який містить маркер у коментарі `30000000-0000-0000-0000-000000000005`).
* **Очікуваний результат:**
  * У JSON-відповіді API рядок маркера збережено без спотворень;
  * У DOM (`#description` та `#comments`) містяться виключно текстові вузли (`#description.childElementCount === 0`), елемент `<img>` не створено;
  * Атрибут `data-lab05-marker` дорівнює `null`;
  * Складний легітимний текст (`O'Brien "терміново"`, `5 < 7 і 9 > 3`, `Київ — Ω`, `<b>жирний</b>`, 3900 символів) відображається без помилок.
* **Негативний контроль:** на `vulnerable_commit` без CSP той самий маркер створював `<img>` і встановлював `data-lab05-marker="executed"`.

### REG-CORS-01 (Відтворювана процедура перевірки CORS Policy)
* **Частина 1 (Browser evidence):** при запущених probes `:4173` та `:4174` сторінка `http://localhost:4173` успішно виконує simple GET, preflighted GET (`X-Lab-Cors-Probe`) та credentialed GET (`/api/incidents`), а на `http://localhost:4174` JavaScript отримує відмову CORS.
* **Частина 2 (HTTP evidence):** виконання команд:
  ```powershell
  curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4173" "http://localhost:5080/health"
  curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4174" "http://localhost:5080/health"