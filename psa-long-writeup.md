# We were hit by PolinRider. Here's what it looked like, how to check yourself, and what actually stopped it

*By Ariel Nurieli. November 9, 2026.*

**Summary.** Between August and November 2026, a build-time injector matching public reporting on **PolinRider** pushed malicious commits to about 60 of our repositories across 4 GitHub orgs and accounts, in four waves. PolinRider is attributed to the DPRK / Lazarus "Contagious Interview" cluster and belongs to the EtherHiding family, which resolves its C2 through blockchain transactions. The pushes came from the attacker's own host, using our own tokens, and they look like our own commits. This post covers what we saw, the indicators, a read-only way to check your machine and repos, and the defenses that actually worked. We're a small team, and we're publishing this because the public write-ups helped us. **Have you seen this pattern? We'd like to compare notes.**

---

## 1. What happened

### How it got in
Around **2026-08-18 to 08-20**, an infected project was built on one developer's Mac. Building it ran the payload. One thing the payload did was **patch GitHub Desktop's `main.js`** (the app's Electron entry point):

- The payload sat on **line 4**, after hundreds of spaces, so it was off-screen in any editor.
- The marker was `global['e']='app-GitHubDesktop-eval';global.i="A11--#"`.
- The original file was saved next to it as **`main.js.inz.orig`**.

A patched Git client gets the attacker everything that client can reach. GitHub Desktop's OAuth token had `repo` and `workflow` scope, and it had never been revoked.

Public research describes the same Electron-injection technique against VS Code and Discord on Windows, with the marker labels `app-vscode-eval` and `app-discord-eval` ([deepwoodssec analysis](https://github.com/deepwoodssec/polinrider-reactime-analysis)). We didn't find the GitHub Desktop / macOS variant in the public write-ups we read.

### How it spread
The attacker used tokens that could act as us: the GitHub Desktop OAuth token, GitHub CLI tokens, and possibly agent or CI tokens. With them, the attacker **re-created our genuine commits with the payload added** and force-pushed them. Author name, email and date were kept, so the commits look like ours in the GitHub UI.

Each infected branch also re-infects whoever builds it. That includes a teammate's laptop, a CI runner, and Vercel. So revoking "the" token once wasn't enough. Some tokens survived, and infected branches kept stealing fresh ones.

### Timeline (UTC unless noted)

| When | What |
|---|---|
| ~2026-08-18 to 08-20 | An infected build runs on a developer Mac. GitHub Desktop `main.js` is patched. |
| 2026-09-01 | **Wave 1.** Malicious pushes to many repos. We cleaned up on 2026-09-02, but history still contained the payload. |
| 2026-10-19 to 10-21 | **Wave 2.** This wave came from Windows pusher tooling (`temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`, `branch_structure.json`). |
| 2026-11-02 | **Wave 3.** Token-based force-pushes across about 60 repos. This time the committer name was the full name, and the committer offset was exactly 1 hour behind the author's. |
| 2026-11-06 22:48 to 23:11 | **Wave 4.** 153 force-pushes in two passes. Within 20 minutes, Vercel ran **89 builds of attacker commits, 14 of them production deploys**. |

Across all four waves, about 60 repos in 4 GitHub orgs/accounts were affected.

---

## 2. How to tell if you're hit

### Check the shape of files, not the strings in them
The strings change between variants. Our first string-based greps missed several. These checks look at shape instead, and they caught every variant we saw:

1. **Config files with a hidden tail.** Look at `postcss`, `eslint`, `babel`, `tailwind`, `jest`, `next`, `vite` and similar config files. The infected ones have a 13 to 26 KB obfuscated line, appended after 200 to 300 spaces, usually right after `export default config;`. Often a `createRequire` shim is prepended at the top as well. A clean `postcss.config.mjs` is about 94 bytes.
   ```bash
   find . \( -name "*.config.js" -o -name "*.config.mjs" -o -name "*.config.cjs" -o -name "*.config.ts" \) \
     -not -path "*/node_modules/*" -print0 | xargs -0 awk 'length($0)>2000{print FILENAME": line "FNR" ("length($0)" chars)"; nextfile}'
   ```
   Any output means infected.
2. **Rewritten `package.json` scripts.** Look for a root `api.js` or `init` loader file, with scripts rewritten to `node api.js && next build` or `node init && next dev`.
3. **A VS Code / Cursor task that runs on folder open.** `.vscode/tasks.json` contains a hidden task with `"runOptions": {"runOn": "folderOpen"}`. The task runs a "font" that is really JavaScript: `public/fonts/fa-solid-500.woff2`, `fa-solid.lkf`, `fa-brand-400.woff`, or `*.orc`. It comes with `"task.allowAutomaticTasks": true` in `.vscode/settings.json`, and a real Font Awesome folder sits next to it as a decoy. A real font file starts with `wOF2`, `wOFF`, `OTTO` or `00 01 00 00`, and a fake one starts with readable JavaScript.
4. **A `next.config.ts` loader.** It contains an IIFE that does `atob(process.env.AUTH_API_KEY)`, fetches that URL with node-fetch, and evals the response. `"dotenv": "^8.2.0"` and `"node-fetch": "^3.3.2"` get added to dependencies. A **`.env`** file is committed with `AUTH_API_KEY="aHR0c..."`, which is base64 of the C2 URL.
5. **A Python variant.** `utils/transport.py` resolves its payload through an Ethereum address.
6. **`.gitignore` edits.** New lines hide the pusher tooling (`temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`, `branch_structure.json`), and the existing ignores for `.env` and `.vscode` are removed so the payload files get committed.

### Commit fingerprints
Dates are faked, and the GitHub UI converts everything to UTC, which hides the tell. Look at the raw objects:
```bash
git log --all --format='%h %aI %cI %an | %cn'
```
| Genuine | Injected |
|---|---|
| author offset == committer offset (yours) | committer offset `-07:00` / `-08:00` while the author's is different (waves 1, 2 and 4) |
| committer name == author name | committer name **shortened** (e.g. "Jane" instead of "Jane Doe") |
| | wave 3: full name, but committer offset **exactly 1h behind** the author's |

Your own travel, DST changes and rebases can produce benign mismatches. Treat a fingerprint hit as a reason to look at the commit's diff, not as proof.

### The machine
- **macOS:** `codesign --verify --deep --strict "/Applications/GitHub Desktop.app"` (repeat for VS Code, Cursor, and any other Electron app). A broken seal means files inside the app were modified after signing. This check exposed the patched GitHub Desktop instantly, after an earlier scan had missed it because the scanner mishandled the space in "GitHub Desktop.app".
- Look for leftover `*.inz.orig` files.
- Look for `node -e` processes: `ps -axo pid,command | grep -E "node +-e" | grep -v grep`. Kill any that reference `_t_s`, `verify-human` or `/0x/clb`.
- Check global npm packages, Python `.pth` and `sitecustomize` files, and LaunchAgents.

### GitHub
- Review **Settings → Applications** (OAuth apps and GitHub Apps), **Tokens**, **SSH keys** and the **Security log**, for your account and for every org you own.
- `GET /repos/{owner}/{repo}/activity?activity_type=force_push` lists every force-push with its actor and its `before`/`after` SHAs ([docs](https://docs.github.com/en/rest/repos/repos#list-repository-activities)).

**Read-only tools we're sharing:** a copy-paste audit prompt for Claude Code, Cursor or Codex (`detect-prompt.md`), and a Claude Code skill with two bash/perl scripts (`polinrider-hunter`). Both include a self-test canary in a path with spaces, so that a broken scanner can't report "clean". Both are in this repo: [`detect-prompt.md`](detect-prompt.md) and [`skill/polinrider-hunter`](skill/polinrider-hunter/SKILL.md).

---

## 3. Indicators of compromise

| Type | Indicator | Notes |
|---|---|---|
| File shape | Line > 2000 chars, or code after 150+ blanks, in `*.config.{js,mjs,cjs,ts}` | Primary vector. 13 to 26 KB payload. |
| File | Prepended `import { createRequire } from 'module'; const require = createRequire(import.meta.url);` | Often added together with the payload. |
| File | Root `api.js` / `init`, with scripts like `node api.js && next build` or `node init && next dev` | Loader. |
| File | `.vscode/tasks.json` with `runOn: folderOpen`, plus `task.allowAutomaticTasks: true` | Runs when the folder is opened. |
| File | `public/fonts/fa-solid-500.woff2`, `fa-solid.lkf`, `fa-brand-400.woff`, `*.orc` that are actually JS | Fake fonts. |
| File | `next.config.ts` IIFE doing `atob(process.env.AUTH_API_KEY)`, then node-fetch, then `eval` | Next.js variant. |
| Dependency | `"dotenv": "^8.2.0"`, `"node-fetch": "^3.3.2"` added | Next.js variant. |
| C2 | `hxxps://auth-confirm-eight[.]vercel[.]app/api` (defanged; base64 in `.env` as `AUTH_API_KEY="aHR0c..."`) | Next.js variant. |
| Python | `utils/transport.py`, ETH address `0x3b1574417524c11a7403c4b232CAcBb320CceBC6` | Python variant. |
| Tooling | `temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`, `branch_structure.json` (also as new `.gitignore` lines) | Windows pusher. `branch_structure.json` maps the victim's branches. |
| Electron patch | GitHub Desktop `main.js` line 4 after many spaces: `global['e']='app-GitHubDesktop-eval';global.i="A11--#"`; `main.js.inz.orig` | Shows up as a broken codesign seal. |
| Markers | `global['!']`, `global['_V']`, `_t_s`, `verify-human`, `/0x/js`, `/0x/clb` | Bonus signal only. |
| Campaign IDs | `A11-1369-4`, `A9-9259-1`, `A11--#` | |
| Commits | Committer offset `-07:00`/`-08:00` ≠ author's, or exactly 1h behind; shortened committer name | Fake dates. Inspect with `git log`, not the UI. |

The public dossiers list many more indicators, including Vercel-hosted C2 domains, TRON, Aptos and BSC dead-drop addresses, and decoder signatures. See [OpenSourceMalware's PolinRider repo](https://github.com/OpenSourceMalware/PolinRider) and [Socket's write-up](https://socket.dev/blog/polinrider-github-packagist).

---

## 4. Blast radius: what to assume is stolen

The payload runs on:
- `npm install`, `next build`, `next dev`, `vitest` and `npm test`
- **opening the folder** in VS Code or Cursor, when automatic tasks are allowed
- **every CI and Vercel build** of an infected commit

So you should assume all of the following are stolen:
- Everything the infected machine could reach: Git credentials, editor and app tokens, cloud CLIs, `.env` files on disk, and browser sessions.
- **All environment variables of every project that built an infected commit**, in preview or production. For us that was 89 builds in 20 minutes, 14 of them production.

---

## 5. Remediation checklist

Order matters. If you rotate while a machine or branch is still infected, you hand over the new credentials too.

**Contain**
- [ ] Stop building. Pause automatic deploys (Vercel, Netlify, CI) for affected projects.
- [ ] Don't open suspect repos in VS Code or Cursor. Set `"task.allowAutomaticTasks": "off"` globally.
- [ ] Kill beacon processes (`node -e …` referencing `_t_s`, `verify-human` or `/0x/clb`).

**Clean the machine**
- [ ] Run `codesign --verify --deep --strict` on GitHub Desktop, VS Code, Cursor, and every Electron app. **Uninstall and reinstall** any app that fails, from the vendor, then verify again.
- [ ] Search for `*.inz.orig` files. Review global npm packages, Python `.pth`/`sitecustomize`, LaunchAgents, and global git hooks.
- [ ] Scan CI runner `_work` trees, agent and Docker workspaces, and `.next` caches as well.

**Revoke everything, from a clean machine**
- [ ] Revoke **all** GitHub OAuth apps and GitHub App authorizations, **all** PATs, and **all** SSH keys, in your account and in every org. Then re-authorize only what you need. We revoked some at first and it wasn't enough, because one surviving token was enough for the next wave.
- [ ] Sign out of `gh` and GitHub Desktop. Rotate any agent, bot or CI tokens that can push.

**Rotate project secrets**
- [ ] For **every project that built an infected commit**, rotate every env var: database URLs, API keys, OAuth client secrets, webhook secrets, and signing keys. "Cleaned the code" doesn't mean "safe" if the credentials weren't rotated.

**Restore branches exactly**
- [ ] For each repo, run `gh api "repos/OWNER/REPO/activity?activity_type=force_push"`. It gives `before`/`after` SHAs for every force-push.
- [ ] Scan each `before` commit before restoring to it, because an earlier wave may already be in it. Otherwise, remove the payload with a normal commit.
- [ ] **Never merge, rebase or check out old infected commits.** History still contains the payload.

**Prevent**
- [ ] Add rulesets or branch protection that **block force-pushes and deletions** on default branches ([about rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)). Our repos with rulesets were untouched in wave 4. On GitHub Free these aren't available for private repos, which is exactly where we were exposed.
- [ ] Commit a **shape-based scanner**, a **pre-push hook**, and a **CI check** that fails on findings. On our protected repos this combination caught the injection. Make sure the scanner handles paths with spaces, and test it with a canary.
- [ ] Scan before every `npm install`, build or test on a repo you didn't just write yourself.

---

## 6. What worked, and what didn't

**Worked**
- **Rulesets that block force-push on default branches.** Repos that had them were untouched in wave 4.
- **A committed scanner, a pre-push hook and a `malware-scan` GitHub Action.** Together they caught the injection on protected repos.
- **GitHub's Activity API**, which let us restore every branch to its exact pre-attack SHA.
- **`codesign --verify --deep --strict`**, which exposed the patched GitHub Desktop in seconds.

**Didn't work**
- **String-based greps.** The variants change their strings.
- **Revoking only some tokens.**
- **Cleaning up without rotating credentials.**
- **Scanners that mishandle paths with spaces.** That's how we missed the GitHub Desktop patch once.

---

## 7. A call to the industry

None of this is a novel exploit. It works because developer tooling trusts too much by default. What would have helped us:

**GitHub**
- Basic force-push and deletion protection on default branches for **private repos on free plans**. Today the users with the least security staff get the least protection.
- **Alert repository owners on force-pushes** to default branches, especially bursts across many repos from one token.
- Show token-level attribution on pushes. Surface "this commit's committer identity or timezone doesn't match its author" in the UI instead of normalizing it away.
- A single "revoke all OAuth/App tokens and sessions" button, plus last-used data for every authorization.
- Make hidden content obvious in diffs, for example lines with huge whitespace runs.

**Vercel and other CI/CD platforms**
- Optionally **refuse, or hold for approval, production builds triggered by a force-push**, or by commits whose fingerprint differs from the repo's history.
- Alert when many projects in a team build in a burst. Make "which env vars did this build have access to" easy to answer.

**npm and package registries**
- Config files executing at build time is the core weakness. Flag published packages whose config files contain long whitespace-hidden tails, and support provenance and trusted publishing as the default.

**Editor vendors (VS Code, Cursor, and other forks)**
- Treat `runOn: folderOpen` tasks as high-risk even in trusted workspaces. Show the command before the first run, and never let a repo's own `.vscode/settings.json` turn automatic tasks on.
- Render long-whitespace hidden tails visibly.
- Electron apps should verify their own integrity at launch. ASAR integrity and the other integrity fuses exist, but a patched `main.js` ran without complaint.

---

## 8. References (public research)

- OpenSourceMalware, *PolinRider* dossier: https://github.com/OpenSourceMalware/PolinRider
- OpenSourceMalware, "Hundreds of GitHub Repos Compromised By DPRK's PolinRider Campaign" (2026-03-08): https://opensourcemalware.com/blog/polinrider-dprk-compromised-hundreds-of-github-repos
- OpenSourceMalware, "PolinRider Confirmed Footprint Grows 6.5x Since March" (2026-07-15): https://opensourcemalware.com/blog/polinrider-blast-radius-grows
- OpenSourceMalware, "PolinRider Jumps the Fence to Go, Packagist, npm, PyPI" (2026-07-08): https://opensourcemalware.com/blog/polinrider-jumps-the-fence
- Socket, "PolinRider Spreads Through Compromised GitHub Accounts and Packagist" (2026-09-17): https://socket.dev/blog/polinrider-github-packagist
- Socket, "PolinRider: North Korea-Linked Supply Chain Campaign Expands Across Open Source Ecosystems": https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
- SafeDep, "astro.config.mjs Supply Chain Attack via Blockchain C2" (2026-06-12), which covers the whitespace diff-hiding technique: https://safedep.io/astro-config-blockchain-c2-supply-chain/
- Microsoft Security, "Developer-targeting campaign using malicious Next.js repositories" (2026-02-24): https://microsoft.com/en-us/security/blog/2026/02/24/c2-developer-targeting-campaign
- deepwoodssec, PolinRider / Reactime analysis, including the Electron-injection component: https://github.com/deepwoodssec/polinrider-reactime-analysis
- GitHub Community, "Auto force push attacking all repos and branches" #198490: https://github.com/orgs/community/discussions/198490
- GitGuardian, "The GhostAction Campaign" (2025-09-05). This is a separate, earlier campaign that abused compromised GitHub accounts through malicious workflows: https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/
- GitHub Docs, List repository activities: https://docs.github.com/en/rest/repos/repos#list-repository-activities
- VS Code Docs, Tasks (`runOn: folderOpen`, `task.allowAutomaticTasks`): https://code.visualstudio.com/docs/debugtest/tasks

*If you've seen the GitHub Desktop / `app-GitHubDesktop-eval` variant, the `auth-confirm-eight` C2, or the 1-hour-offset commit pattern, please [open an issue](../../issues) on this repo.*
