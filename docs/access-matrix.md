# Матриця контролю доступу (Політика відмов: 404 Not Found)

| Дія | Анонім | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---|---|---|---|---|---|
| Перегляд списку | deny (401) | allow (лише власні) | allow (всі) | deny | Так для Reporter | Реалізовано (query scoping) |
| Перегляд деталей | deny (401) | allow (owner); deny (404) | allow (для аналізу) | deny | Так | Реалізовано (IAuthorizationHandler) |
| Створення інциденту | deny (401) | allow (для себе) | allow | deny | Сервер призначає власника | Baseline |
| Update content | deny (401) | allow (owner); deny (404) | deny (403) | deny | Так | Реалізовано (IAuthorizationHandler) |
| Delete | deny (401) | allow (owner); deny (404) | deny (403) | deny | Так | Реалізовано (IAuthorizationHandler) |
| Зміна severity/status (Triage) | deny (401) | deny (403) | allow (лише New -> Triaged) | deny | Ні (залежить від ролі) | Реалізовано (IAuthorizationHandler) |
| Перегляд internal comment | deny (401) | deny | allow (після авторизації батьківського) | deny | Ні | Реалізовано |