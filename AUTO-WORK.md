# AUTO-WORK.md — Autonomous Work Directive

## Overview

When instructed to "work autonomously" or "continue autonomous work," follow this directive. Work in batches of parallel subagents, committing, pushing, and tagging after each batch. Check for a STOP signal between batches.

---

## Work Loop

1. **Check for STOP file** — Before starting each batch, check if a file named `STOP` exists anywhere under the repo root (`find /home/static/dev-wsl/admin-portal -name "STOP" -maxdepth 3`). If found, stop immediately and prompt the user.

2. **Plan the batch** — Identify 3-6 independent, non-overlapping improvements or features to work on. Each task should be scoped to complete in a single subagent run. Prioritize:
   - Bugs and broken functionality
   - UI/UX consistency fixes
   - Missing CRUD operations or incomplete feature areas
   - Feature plan items (FEATURE-*.md) in order
   - Polish, accessibility, and responsive design

3. **Launch subagents in parallel** — Spin up one agent per task. Each agent should:
   - Read existing code to understand patterns before making changes
   - Follow established conventions (see CLAUDE.md, project memory)
   - Run `npx tsc --noEmit` to verify no type errors after changes
   - Only modify files relevant to its assigned task
   - Not overlap with other agents' files

4. **Verify results** — After all agents complete:
   - Run a final `npx tsc --noEmit` to catch cross-agent conflicts
   - Spot-check key changes if needed
   - Fix any issues

5. **Commit, push, tag** — Stage all changes, commit with a descriptive message, push to `dev`, and tag as the next minor version (e.g., `v0.101.0`).

6. **Loop** — Go back to step 1.

---

## Tagging Convention

- Increment the minor version for each batch: `v0.101.0`, `v0.102.0`, etc.
- Use `git tag -a vX.Y.Z -m "description"` for annotated tags.
- Push tags with `git push origin dev --tags`.

---

## Branching

- All autonomous work happens on the `dev` branch.
- When requested, create an `alpha` branch off `dev` before continuing on `dev`.

---

## STOP Protocol

- Check for `STOP` file before each batch.
- If found, immediately stop and prompt the user with a summary of what was completed and what was planned next.
- The user will remove the STOP file when ready to resume.

---

## What NOT to Do

- Do not push to `main` — only `dev`.
- Do not create documentation files unless explicitly requested.
- Do not refactor working code just for style — focus on functionality.
- Do not modify generated files (`*.gen.ts`, `openapi.json`) — those come from `make types`.
- Do not run database migrations or destructive operations.
- Do not work on the same files across multiple parallel agents.
