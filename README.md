# We got hacked by the space bar

*About 60 repos. Two months of malware with our names on it. The embarrassing version, and how to check if it happened to you.*

---

This is embarrassing to publish. We build with AI for a living, and we are a small team that should have known better. We're publishing it anyway, because nothing about this needed us to be careless in some special way. It needed us to be normal.

Around August 18, our AI found us a project on the internet. It either picked it on its own or recommended it, and we didn't really care. We just went with it. One of us built it on a Mac. One build. That build patched the GitHub Desktop app and handed someone else a token that could act as us.

Starting September 1, that someone pushed code to about 60 of our repos across 4 GitHub orgs and accounts. They took our real commits and re-created them. Same author, same email, same dates, same messages. One thing added.

The thing added was a line of obfuscated malware at the end of a config file, the kind nobody opens. `postcss.config.mjs`. `eslint`. `tailwind`. It sat behind about 300 blank spaces, so it was off the edge of the screen. You could open the file, look right at it, and see `export default config;` and nothing else.

A clean `postcss.config.mjs` is about 94 bytes. Ours were up to 26 KB.

We found it. We cleaned it up on September 2. It came back in October. We cleaned it again. It came back on November 2. It came back on November 6, and that time Vercel built 89 attacker commits in 20 minutes and shipped 14 of them to production.

It kept coming back because we kept doing half the job. We revoked some tokens. One survivor was enough.

Then we scanned the Mac, and the scan said clean. It wasn't. Our scanner choked on the space in the name `GitHub Desktop.app` and walked right past the infected app.

300 spaces hid the malware. One space hid the infected app.

## Why we're telling you

The activity matches public reporting on **PolinRider**, a campaign researchers tie to North Korea's "Contagious Interview" cluster. It has hit hundreds of repos. We're just the ones writing it up with our own embarrassment attached.

We all pull code from strangers now, all day. A repo from a tweet. A starter template. A package somebody's agent suggested. More and more, we're not even the one choosing. Claude or Cursor picks the package, picks the template, runs the install, and we go get coffee.

Your AI has no idea who wrote that repo. It will run it anyway, on the machine that holds all your keys.

Know what you're running. Especially when you didn't pick it.

## Check yourself

**Yes, we see the irony.** You just read a warning about random repos, on a random repo. So read before you run. Everything here is short, plain text, and read-only.

**Thirty seconds, no install.** Run this from the folder that holds your projects:

```bash
find . -type f -name "*.config.*" -not -path "*/node_modules/*" -exec awk 'length($0)>2000{print FILENAME; nextfile}' {} +
```

No output is what you want. If it prints a file, don't build, don't `npm install`, and don't open that folder in VS Code or Cursor (the payload can run on folder open). Inspect the file from the terminal.

That check covers the most common variant only. For the rest:

| Tool | What it does |
|---|---|
| [`detect-prompt.md`](detect-prompt.md) | Paste it into Claude Code, Cursor or Codex. Your agent audits your machine and repos, read-only, and asks before changing anything. |
| [`skill/polinrider-hunter`](skill/polinrider-hunter/SKILL.md) | A Claude Code skill with two bash scripts: one for repos, one for the machine. Each tests itself on a canary in a path with spaces first, so a broken scanner can't tell you "clean". We learned that one the hard way. |

## What happened, in order

| When (UTC) | What |
|---|---|
| ~Aug 18 to 20 | An infected build runs on a developer Mac. GitHub Desktop's `main.js` gets patched. |
| Sep 1 | **Wave 1.** Malicious pushes to many repos. We clean up on Sep 2, but history still holds the payload. |
| Oct 19 to 21 | **Wave 2.** Pushed from Windows tooling (`temp_auto_push.bat` and friends). |
| Nov 2 | **Wave 3.** Token-based force-pushes across about 60 repos. |
| Nov 6, 22:48 to 23:11 | **Wave 4.** 153 force-pushes. Vercel runs 89 builds of attacker commits, 14 of them production. |

## What worked, what didn't

**Worked**
- Rulesets that block force-pushes on default branches. Repos that had them came through wave 4 untouched. GitHub Free doesn't offer them on private repos, which is where we got hit.
- A scanner that checks the shape of a file (a 2,000 character config line, code after a run of blanks) instead of matching strings.
- `codesign --verify --deep --strict` on macOS apps. A broken seal exposed the patched GitHub Desktop in seconds.
- GitHub's Activity API, which lists the before and after SHA of every force-push, so we could restore branches exactly.

**Didn't**
- Grepping for known strings. The variants change them.
- Revoking some tokens. It has to be all of them, from a clean machine.
- Cleaning the code without rotating the secrets. If an infected commit built, assume every env var on that project is stolen.
- A scanner that had never been tested on a path with a space in it.

## Going deeper

The [full write-up](psa-long-writeup.md) has everything: how to tell if you're hit, the [indicators of compromise](psa-long-writeup.md#3-indicators-of-compromise), the [remediation checklist](psa-long-writeup.md#5-remediation-checklist) (the order matters), what we'd ask GitHub, Vercel and editor vendors to change, and every source.

## Credit

[OpenSourceMalware](https://github.com/OpenSourceMalware/PolinRider), [Socket](https://socket.dev/blog/polinrider-github-packagist), [SafeDep](https://safedep.io/astro-config-blockchain-c2-supply-chain/) and [Microsoft](https://microsoft.com/en-us/security/blog/2026/02/24/c2-developer-targeting-campaign) published the research that made this possible to untangle. We just added our part.

## Seen this?

Especially the GitHub Desktop variant, or commits where the committer time is exactly one hour behind the author's. Open an issue. We'd like to compare notes.
