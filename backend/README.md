# Backend: регистрация и авторизация

Реализованы ФТ-01–03 и требования к выходу и восстановлению пароля из TZ_Ponimayu_kod_v1_1.docx.

## Запуск

Требуются Java 21, PostgreSQL и SMTP-сервер. Создайте пустую БД codecomprehension или укажите существующую через DB_URL. Таблицы app_users и auth_tokens создаются при запуске (schema.sql); существующие данные не удаляются. Для последующих изменений схемы потребуется система миграций.

В PowerShell из папки backend:

    $env:DB_URL = 'jdbc:postgresql://localhost:5432/codecomprehension'
    $env:DB_USERNAME = 'postgres'
    $env:DB_PASSWORD = '<пароль вашей БД>'
    $env:MAIL_HOST = '<SMTP host>'
    $env:MAIL_PORT = '587'
    $env:MAIL_USERNAME = '<SMTP username>'
    $env:MAIL_PASSWORD = '<SMTP password>'
    $env:MAIL_AUTH = 'true'
    $env:MAIL_STARTTLS = 'true'
    $env:MAIL_FROM = '<адрес отправителя>'
    $env:PUBLIC_URL = 'http://localhost:8080'
    $env:ALLOWED_ORIGINS = 'http://localhost:3000'
    .\mvnw.cmd spring-boot:run

Для локальной почты можно использовать SMTP на localhost:1025 без авторизации (значения по умолчанию). Без рабочего SMTP регистрация возвращает 503 и откатывается. Пароли и токены не выводятся в логи и ответы регистрации.

Первый администратор создаётся при запуске из ADMIN_EMAIL и ADMIN_PASSWORD, если такой адрес ещё не зарегистрирован. Существующий USER не повышается до ADMIN. Администратор сразу подтверждён; вход выполняется тем же API. После создания удалите ADMIN_PASSWORD из окружения. Общедоступного API создания администратора нет; переданное клиентом поле role не назначает права.

## API

Все тела запросов — JSON, Content-Type: application/json. Почта нормализуется к нижнему регистру. Пароль: 8–72 символа и не более 72 байт UTF-8.

| Метод | Путь | Тело / параметры | Результат |
|---|---|---|---|
| POST | /api/auth/register | {"email":"user@example.com","password":"strong-password"} | 201, письмо подтверждения |
| GET | /api/auth/verify-email | ?token=из-письма | 200, подтверждение |
| POST | /api/auth/login | email, password | 200, accessToken, tokenType, expiresIn, user |
| GET | /api/auth/me | Bearer token | id, email, role |
| POST | /api/auth/logout | Bearer token | 204, отзыв текущего токена |
| POST | /api/auth/forgot-password | {"email":"user@example.com"} | 200, одинаковое сообщение для неизвестной почты |
| GET | /api/auth/reset-password | ?token=из-письма | Инструкция для API-клиента |
| POST | /api/auth/reset-password | {"token":"из-письма","password":"new-password"} | 200, отзыв всех входов |
| GET | /api/admin/me | Bearer token ADMIN | данные текущего администратора |

Защищённые запросы требуют заголовок Authorization: Bearer <accessToken>. Сессия действует 12 часов. Токен подтверждения действует 24 часа, восстановления — 30 минут; оба одноразовые. Фронтенд позже сможет заменить страницу инструкции восстановления формой.

Пример проверки через PowerShell:

    $body = @{email='user@example.com'; password='strong-password'} | ConvertTo-Json
    Invoke-RestMethod http://localhost:8080/api/auth/register -Method Post -ContentType application/json -Body $body
    # Откройте ссылку из письма, затем:
    $login = Invoke-RestMethod http://localhost:8080/api/auth/login -Method Post -ContentType application/json -Body $body
    $headers = @{Authorization="Bearer $($login.accessToken)"}
    Invoke-RestMethod http://localhost:8080/api/auth/me -Headers $headers
    Invoke-RestMethod http://localhost:8080/api/auth/logout -Method Post -Headers $headers

Ошибки имеют вид {"message":"..."}: 400 — неверный ввод или ссылка; 401 — неверные данные/нет входа; 403 — неподтверждённая почта, блокировка или недостаточные права; 409 — занятая почта; 503 — отправка письма не удалась.

Пароли защищены BCrypt (cost 12). Непрозрачные случайные токены содержат 256 бит случайности; в БД сохраняются только SHA-256 хэши. Блокировка и подтверждение проверяются при каждом запросе. USER не допускается к /api/admin/**. Административное управление блокировками и проекты не входят в текущий этап.

CSRF отключён для API с явно передаваемым Bearer-заголовком; cookie-аутентификация не используется. CORS разрешает только настроенные origins. Для публикации нужны HTTPS и ограничение частоты запросов на вход/регистрацию/восстановление на шлюзе.

## Проверка

    .\mvnw.cmd test

Добавлены модульные тесты нормализации, хэширования, неверного пароля, блокировки и неподтверждённого аккаунта. Интеграционный прогон с реальными PostgreSQL и SMTP необходим для проверки отправки писем и транзакций. В текущей агентской среде запуск Maven запрещён операционной системой (Access denied); успешная сборка пока не подтверждена.
