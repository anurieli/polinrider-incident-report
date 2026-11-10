---
name: polinrider-hunter
description: Read-only hunt for the PolinRider / EtherHiding supply-chain injection (DPRK "Contagious Interview" family) in local git repos, on the developer machine, and in GitHub force-push history. Use when the user asks to "check for PolinRider", "check for EtherHiding", "scan my repos for malware", "check for supply chain injection", "is my repo infected", "look for hidden code in postcss/eslint/tailwind/next config", "check for malicious force-pushes", "verify GitHub Desktop / VS Code / Cursor is not patched", or before running npm install / build / test in a repo that might be compromised.
---

# polinrider-hunter

Finds the PolinRider / EtherHiding build-time injector and its side effects. **Everything this skill runs is read-only.** It reports findings and then asks the user before changing anything.

## Ground rules (follow them strictly)

1. **Do not build, install, test, or run anything in a suspect repo** (`npm install`, `npm test`, `vitest`, `next build`, `next dev`, `pnpm`, `bun`, `python` entry points, etc.) until the scan says CLEAN. Payloads run on install, build, test, dev, on VS Code/Cursor folder open, and in CI/Vercel builds.
2. **Do not open suspect folders in VS Code/Cursor** to inspect them. Use `cat`, `less -S`, `perl`, or the scanner instead.
3. **Do not modify, delete, commit, push, fetch, or force-push anything** unless the user explicitly says so after seeing the report. Remediation is a separate, user-approved step.
4. **Never print secrets.** Don't cat `.env` files, token stores, or keychains. The scanner only prints the *decoded host* of base64 URLs it finds in `.env`.
5. **Check shape, not strings.** The variants change their strings often. Treat the marker strings as a bonus signal. The primary checks are a code tail hidden after a long whitespace run, very long lines in configs, fonts that aren't fonts, folderOpen tasks, rewritten `package.json` scripts, and broken code-signature seals.
6. **Trust the self-test.** Both scripts plant harmless canaries in a temp path that contains spaces, then check that they detect them. If the self-test fails, say so and don't report "clean". A scanner that mishandled paths with spaces once missed a patched GitHub Desktop.

## Steps

### 1. Ask what to scan
Ask which directories hold the user's repos. Common answers are `~/Projects`, `~/code`, `~/src`, `~/Desktop`, CI runner `_work` dirs, Docker or agent workspaces, and `.next` caches. Ask before you run `--github`, because it makes many API calls.

### 2. Scan repositories
```bash
bash "<skill-dir>/scripts/scan.sh" ~/Projects ~/Desktop     # any number of roots; paths with spaces are fine
```
- It scans working-tree files (skipping `node_modules`; add `--deps` to include them). It also reads every local and remote-tracking **branch tip straight from git objects**, so infected branches that aren't checked out are found too.
- It checks commit fingerprints. A re-committed commit keeps the genuine author but has a committer whose timezone is `-07:00`/`-08:00` while the author's isn't, or a committer offset exactly 1h behind the author, or a shortened committer name such as "Jane" for "Jane Doe".
- It flags pusher tooling (`temp_auto_push.bat`, `temp_interactive_push.bat`, `branch_structure.json`) that is still reachable in history.
- It never fetches. Tell the user that remote-tracking refs are only as fresh as their last fetch, and ask if they want to `git fetch` first. Fetching is safe because it doesn't execute anything, but it does change local refs.
- Exit codes: `0` CLEAN, `1` INFECTED, `2` SUSPICIOUS, `3` self-test failed or scanner error.

### 3. Scan the machine
```bash
bash "<skill-dir>/scripts/scan_machine.sh"              # add --all-apps to codesign every app (slow)
bash "<skill-dir>/scripts/scan_machine.sh" --github     # also list force-pushes via read-only `gh api` (last 120 days; --days N)
```
It runs these checks:
- On macOS it runs `codesign --verify --deep --strict` on every Electron app plus a list of known editor and Git apps. A **broken seal** means files inside the app changed after signing. The GitHub Desktop `main.js` patch shows up exactly this way.
- It scans JS inside those apps (`main.js`, `app.asar`) for hidden tails and `app-*-eval` markers.
- It looks for leftover `*.inz.orig` / `*.inz.cjs` files, which are originals saved by the patcher.
- It scans global npm trees by path. It **never runs npm or node**, because a patched global npm would execute.
- It checks Python startup hooks: `.pth` files with code, plus `sitecustomize` and `usercustomize`. It runs python3 only with `-S -I`, so no `.pth` file executes.
- It reviews LaunchAgents and LaunchDaemons on macOS, and autostart, systemd user units, and crontab on Linux.
- It looks for `node -e` and inline-python processes, using a process snapshot taken before the scanner's own perl processes start.
- It checks global git hooks and templates, shell rc files, and editor settings (`task.allowAutomaticTasks`, Workspace Trust).
- It scans editor extension JS, unless you pass `--no-extensions`.

### 4. Things the scripts cannot see. Ask the user to check these, or check them yourself in a browser if you have one
- https://github.com/settings/applications: authorized OAuth apps and GitHub Apps. GitHub Desktop, GitHub CLI, editors, and AI agents all appear here. These tokens survive password changes.
- https://github.com/settings/tokens: classic and fine-grained PATs.
- https://github.com/settings/keys: SSH and GPG keys.
- https://github.com/settings/security-log: unexpected `oauth_authorization.create`, token, or key events.
- The same pages for every org they own (org settings, then OAuth app policy, then the audit log).
- Vercel, Netlify, or other CI deployments built from commits they don't recognise. **Every env var of a project that built an infected commit should be considered stolen.**

### 5. Report
Report in this order, and keep it short:
1. Self-test result for each script.
2. **INFECTED** findings, grouped by repo or by machine area, with the file and line, and why each one matters.
3. **SUSPICIOUS** findings that need a human decision. Call out likely false positives honestly. For example, a fingerprint mismatch can come from the user's own travel or a DST change during a rebase, and a `folderOpen` task can be one the user wrote.
4. What was **not** checked: unfetched remotes, Windows machines, other team members' machines, CI caches, and GitHub settings pages.
5. A proposed remediation plan (see below). Then **ask** which steps, if any, they want you to perform.

## Remediation plan to propose (don't execute without explicit approval)

Order matters. Rotating credentials while an infected machine or branch is still active just hands over the new ones.

1. **Contain.** Stop building. Pause automatic deploys. Kill beacon processes. Don't open infected folders in editors.
2. **Clean the machine.** Quit, delete, and reinstall any app with a broken seal from the vendor, then re-verify with `codesign`. Remove patcher leftovers and malicious launch items or `.pth` files after reviewing them.
3. **Revoke all of it, from a clean machine.** That means every GitHub OAuth app and GitHub App authorization, every PAT, and every SSH key. Sign out of `gh` (`gh auth logout`) and GitHub Desktop. Rotate any CI and agent tokens that could push. Revoking only some of them failed in practice, because one surviving token is enough for the next wave.
4. **Rotate project secrets** for every project whose CI or Vercel ran an infected commit. Treat its env vars as stolen.
5. **Restore branches exactly.** `GET /repos/{owner}/{repo}/activity?activity_type=force_push` lists each force-push with `before`/`after` SHAs. Restore from the `before` SHA, and only after confirming that `before` is itself clean (run the scanner on it). Alternatively, remove the payload with a normal commit. **Never merge, rebase, or check out old infected commits.**
6. **Prevent.**
   - Add rulesets or branch protection that block force-push and deletion on default branches. On GitHub Free these aren't available for private repos.
   - Commit a shape-based scanner, a pre-push hook, and a CI job that fails on findings.
   - Set `task.allowAutomaticTasks` to `off` and keep Workspace Trust on.
   - Re-run this skill after every cleanup.

## Interpreting common findings

| Check | Meaning |
|---|---|
| `hidden-tail` / `config-long-line` | Code appended after hundreds of blanks on a config line, usually the last line after `export default ...`. Clean configs are tiny, so this is the main campaign vector. |
| `createRequire-shim` | Prepended `import { createRequire } from 'module'`, often added together with the payload. It can be legitimate. |
| `pkg-script-loader` | A `node api.js && next build` or `node init && next dev` style rewrite. |
| `vscode-folderOpen-task` + `fake-font` | `.vscode/tasks.json` auto-runs a "font" (`.woff2`, `.lkf`, `.orc`) that is really JS. |
| `nextconfig-env-loader` / `env-c2` | `next.config` runs `atob(process.env.X)`, fetches the result, and evals it, with the C2 URL base64-encoded in `.env`. |
| `gitignore-pusher` | `.gitignore` edited to hide the Windows force-push tooling. |
| `commit-fingerprint` | A genuine commit re-created on the attacker's host. Check with `git log --format='%aI %cI %an %cn'`. The GitHub UI normalises to UTC and hides the tell. |
| `codesign-broken` | An app was modified after signing. Reinstall it, then treat that app's stored tokens as stolen. |
| `inz-leftover` | The patcher saved the original file (for example `main.js.inz.orig`). The sibling file is the patched one. |

Public research: OpenSourceMalware PolinRider dossier (https://github.com/OpenSourceMalware/PolinRider), Socket (https://socket.dev/blog/polinrider-github-packagist), Microsoft (https://microsoft.com/en-us/security/blog/2026/02/24/c2-developer-targeting-campaign).
