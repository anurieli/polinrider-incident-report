# PolinRider / EtherHiding self-audit prompt

Paste everything inside the box below into Claude Code, Cursor (agent mode), Codex, or any coding agent that can run shell commands. The prompt is **read-only by default**. The agent reports what it finds and asks before it changes anything.

It works best on macOS or Linux. On Windows, run it inside Git Bash or WSL, and also check the Windows-specific items it mentions.

---

````text
You are auditing my machine and my git repositories for the PolinRider / EtherHiding
supply-chain campaign (DPRK "Contagious Interview" family). Public background:
https://github.com/OpenSourceMalware/PolinRider and https://socket.dev/blog/polinrider-github-packagist

STRICT RULES - follow all of them:
- READ-ONLY. Do not modify, delete, move, commit, push, fetch, checkout, reset or
  install anything. Do not kill processes. Do not change settings. Writing temp files
  under $TMPDIR for your own analysis is fine.
- NEVER run npm/pnpm/yarn/bun install, npm test, vitest, jest, next build/dev, vite,
  or any project script, and never run `node` or `npm` at all (a patched global npm
  would execute). If you need Python, run it only as `python3 -S -I` (so no .pth
  file executes). Do not open suspect folders in an editor.
- NEVER print secrets: do not cat .env files, token stores, keychains, ~/.npmrc,
  ~/.config/gh/hosts.yml or ~/.git-credentials. For .env files report only the
  variable NAME and the decoded HOST of any base64-looking URL value.
- Check SHAPE, not just strings. These variants rotate strings; marker strings are
  a bonus signal only.
- Handle paths with spaces correctly everywhere: use `find ... -print0 | xargs -0`
  or `while IFS= read -r -d ''`. Before trusting any CLEAN result, PROVE your
  method works: create a harmless canary in "$TMPDIR/pr canary/dir with space/"
  (a postcss.config.mjs whose last line is `export default {};` + 300 spaces +
  2100 'x' characters, and a file fonts/x.woff2 that contains `console.log(1)`),
  run your exact detection commands on it, confirm both are flagged, then delete it.
- When finished, give me the report described at the end, then ASK which (if any)
  remediation steps I want you to perform. Do nothing further without my answer.

First ask me which directories contain my repos (suggest ~/Projects, ~/code,
~/src, ~/Desktop, ~/Documents, CI runner _work dirs, Docker/agent workspaces).

=== A. REPOSITORIES (each root I give you; skip node_modules unless I say otherwise) ===
Check working trees AND every local + remote-tracking branch tip (read blobs with
`git ls-tree -r <ref>` + `git cat-file -p <sha>`; never checkout):

A1. Build configs (postcss/tailwind/eslint/babel/jest/vite/vitest/next/nuxt/astro/
    webpack/svelte/... *.config.{js,mjs,cjs,ts,mts,cts}, .*rc.js, gatsby-*.js):
    - any line > 2000 chars  -> INFECTED
    - any line with a non-space char, then 150+ spaces/tabs, then more code
      (payload hidden off-screen, typically after `export default ...;`) -> INFECTED
    - `import { createRequire } from 'module'` prepended at the top -> SUSPICIOUS
    - eval( or a Function constructor in a config -> SUSPICIOUS
A2. next.config.*: an IIFE doing atob(process.env.SOMETHING) -> fetch/node-fetch ->
    eval -> INFECTED. package.json that gained "dotenv": "^8.2.0" together with
    "node-fetch": "^3.3.2" -> SUSPICIOUS.
A3. .env* files: values starting with `aHR0c` (base64 of "http"). Decode, report
    only var name + host. AUTH_API_KEY holding a base64 URL, or the host
    auth-confirm-eight.vercel.app -> INFECTED.
A4. package.json scripts rewritten to run a loader first, e.g.
    "build": "node api.js && next build", "dev": "node init && next dev"
    -> INFECTED; inspect the root api.js / init file (long lines, eval,
    child_process, base64) without executing it.
A5. .vscode/tasks.json with "runOptions": {"runOn": "folderOpen"} -> SUSPICIOUS;
    INFECTED if it runs a font file (public/fonts/fa-solid-500.woff2, fa-solid.lkf,
    fa-brand-400.woff, *.orc), curl/wget, node -e, or a *.vercel.app URL.
    .vscode/settings.json with "task.allowAutomaticTasks": true/"on" -> SUSPICIOUS.
    A real Font Awesome folder next to it is a decoy - still check every file.
A6. Fake fonts: any *.woff/*.woff2/*.ttf/*.otf/*.eot/*.lkf/*.orc whose first bytes
    are not a font signature (wOFF, wOF2, 00 01 00 00, OTTO, true, ttcf) and that is
    mostly printable text -> INFECTED (JavaScript disguised as a font).
A7. Python variant: utils/transport.py or any .py that exec/evals decoded or
    fetched data, or contains 0x3b1574417524c11a7403c4b232CAcBb320CceBC6 -> INFECTED.
A8. .gitignore lines hiding Windows pusher tooling: temp_auto_push.bat,
    temp_interactive_push.bat, config.bat, branch_structure.json -> INFECTED
    (config.bat alone -> SUSPICIOUS). Also flag those files existing anywhere, and
    .gitignore changes that REMOVED .env or .vscode ignores.
A9. Marker strings (bonus): global['!'], global['_V'], global['e']='app-...-eval',
    "A11--#", A11-1369-4, A9-9259-1, _t_s, verify-human, /0x/js, /0x/clb,
    rmcej%otb%, Cot%3t=shtP, _$_1e42, and the *.vercel.app C2 domains listed in the
    OpenSourceMalware dossier.
A10. Commit fingerprints (the injector re-commits my genuine commits from its own
    host, keeping author name/email/date). For each repo run
    `git log --all -n 5000 --format='%H %aI %cI %an|%cn|%ae|%ce'` and flag commits
    where author email == committer email but:
      - committer offset is -07:00 or -08:00 while the author offset is not, or
      - committer offset is exactly 1 hour behind the author offset, or
      - committer name is a shortened form of the author name ("Jane" vs "Jane Doe").
    Skip committer "GitHub <noreply@github.com>". GitHub's web UI shows UTC and
    hides this, so use git locally. Report counts + up to 8 examples per repo, and
    remind me that my own travel/DST/rebases can cause benign mismatches.
A11. History: `git log --all --diff-filter=A --name-only` containing
    temp_auto_push.bat / branch_structure.json -> infected commits still reachable.
A12. Non-sample hooks in .git/hooks and any core.hooksPath: list them, scan content.
Note for each repo when its remote-tracking refs were last fetched; do NOT fetch.

=== B. THIS MACHINE ===
B1. macOS: for every app in /Applications and ~/Applications that contains
    Contents/Frameworks/Electron Framework.framework (plus GitHub Desktop, VS Code,
    Cursor, Windsurf, Discord, Slack even if not detected), run
    `codesign --verify --deep --strict "<app>"`. Any failure other than "not signed"
    = the app was modified after signing -> INFECTED (this campaign patched GitHub
    Desktop's main.js: payload hidden after hundreds of spaces on line 4, marker
    global['e']='app-GitHubDesktop-eval', original kept as main.js.inz.orig).
    Also scan each app's Contents/Resources JS / app.asar for the hidden-tail shape
    and app-*-eval markers.
    Linux: scan Electron apps under /opt, /usr/share, /usr/lib, ~/.local/share the
    same way and verify packages with dpkg -V / rpm -V.
B2. Find leftovers named *.inz.orig / *.inz.cjs (originals saved by the patcher)
    under /Applications, ~/Applications, ~/Library/Application Support, ~/.vscode,
    ~/.cursor, ~/.config and global node_modules -> INFECTED.
B3. Global npm trees (/usr/local/lib/node_modules, /opt/homebrew/lib/node_modules,
    ~/.nvm/versions/node/*/lib/node_modules, ~/.npm-global, volta/fnm dirs): scan
    *.js for hidden tails/markers, list packages with install scripts. Find them by
    path - do not run npm.
B4. Python startup hooks: for each site-packages dir (from
    `python3 -S -I -c 'import site; print(site.getsitepackages(), site.getusersitepackages())'`)
    list *.pth lines starting with `import` (they run on every Python start) and
    flag those with exec/eval/base64/urllib/socket/subprocess; flag any
    sitecustomize.py / usercustomize.py.
B5. Persistence: ~/Library/LaunchAgents, /Library/LaunchAgents,
    /Library/LaunchDaemons (read with `plutil -p`): report non-Apple items and
    flag ones running node, python -c, sh -c, osascript, curl/wget, base64, or
    binaries in /tmp, /Users/Shared or hidden dirs. Linux: ~/.config/autostart,
    ~/.config/systemd/user, `crontab -l`. Windows machines on the team: Task
    Scheduler, Startup folder, Run keys, and any temp_*_push.bat / config.bat.
B6. Processes: `ps -axo pid,ppid,command` - flag `node -e` / `node --eval`
    processes and anything referencing _t_s, verify-human, /0x/clb, /0x/js,
    app-*-eval or *.vercel.app/api. Report only; do not kill.
B7. git config --global core.hooksPath / init.templateDir (scan those hooks);
    shell rc files (~/.zshrc, ~/.bashrc, ~/.profile, ...) for hidden tails,
    `node -e`, `curl | sh`; VS Code / Cursor user settings.json for
    task.allowAutomaticTasks on or security.workspace.trust.enabled false.
B8. Editor extensions (~/.vscode/extensions, ~/.cursor/extensions, ...): scan JS
    for the hidden-tail shape and marker strings.

=== C. GITHUB (only if `gh` is installed and authenticated; read-only `gh api` GETs) ===
C1. List my repos and my orgs' repos; for each call
    `gh api "repos/OWNER/REPO/activity?activity_type=force_push&per_page=100"` and
    list every force-push in the last 120 days: timestamp, actor, ref, before, after.
    Force-pushes I didn't do = compromise. The `before` SHA is what to restore to
    (after scanning that commit too).
C2. `gh api user/keys` - list SSH keys (title + created date).
C3. Tell me to review manually (no complete API exists):
    https://github.com/settings/applications (OAuth apps + GitHub Apps - e.g.
    GitHub Desktop / CLI / editor / agent tokens), https://github.com/settings/tokens,
    https://github.com/settings/keys, https://github.com/settings/security-log, and
    the same for each org I own. Also: which Vercel/Netlify/CI deployments built
    commits I don't recognise (env vars of those projects must be treated as stolen).

=== REPORT FORMAT ===
1. Canary self-test result (must pass, otherwise say results are untrustworthy).
2. VERDICT: INFECTED / SUSPICIOUS / CLEAN.
3. INFECTED findings - grouped by repo / machine area, file:line, why.
4. SUSPICIOUS findings - with an honest note on likely false positives.
5. What you could NOT check.
6. Proposed remediation, in this order, as a plan only:
   contain (stop builds, pause auto-deploys) -> clean/reinstall modified apps
   (re-verify codesign) -> from a CLEAN machine revoke ALL GitHub OAuth apps,
   GitHub App authorizations, PATs and SSH keys (not just some) and re-login ->
   rotate env secrets of every project that built an infected commit -> restore
   force-pushed branches from the Activity API `before` SHAs (verified clean) or
   remove payloads with normal commits; never merge/rebase old infected commits ->
   add force-push-blocking rulesets on default branches, a committed shape-based
   scanner + pre-push hook + CI check, set task.allowAutomaticTasks off.
Then ask me which steps you should do. Wait for my answer.
````
