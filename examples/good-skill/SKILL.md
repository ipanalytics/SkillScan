---
name: good-skill
description: Use when проверяем, что чистый навык проходит проверку без замечаний.
---

# Good skill

A minimal, well-formed skill: the folder name matches `name`, the frontmatter has a
description, there is no shell that could hurt anyone, and every path it mentions is a
placeholder rather than someone's home directory.

## Steps

1. Read the input file the caller passed in.
2. Produce a short report.

Nothing here reaches the network or the shell, so `skillscan` reports zero findings.
