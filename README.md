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

## How we dug out

The first three cleanups failed because we fixed what we could see. The fourth one worked because we stopped guessing and made lists. This is the order we'd do it in again.

**1. Find every push.** We stopped trusting the GitHub UI and pulled the force-push log for every repo from GitHub's Activity API. It records the commit before and after every force-push, along with who did it. That's how we know it was 153 force-pushes on November 6, and which branches they landed on.

**2. Put every branch back exactly where it was.** For each force-push we scanned the "before" commit first, because an earlier wave could already be sitting in it. Then we reset the branch to the last clean commit by its exact SHA, and scanned every remote branch again afterwards. On our main site repo that was 30 branches, all clean.

**3. Find every build that ran it.** The malware runs when the code builds. So we listed every Vercel deployment in the attack window and matched each one to the commit it built. Anything built from an attacker commit counts as a machine that ran the malware.

**4. Check what each of those builds could see.** This is how we answered the question we cared about most: did it reach our clients? A Vercel build only gets the environment variables set for its environment. A preview build never sees a production-only secret. So for every infected build we wrote down exactly which variables it had access to.

**5. Treat the laptop as burned.** `codesign --verify --deep --strict` on every Electron app, reinstall anything with a broken seal from the vendor, and hunt down the leftovers (`*.inz.orig`, odd LaunchAgents, `node -e` processes).

**6. Revoke everything, from a clean machine.** Every OAuth app, every personal token, every SSH key, in every account and every org. People count too. A compromised account loses admin until its machine is clean. We learned that one late: the account that had been used against us was still an org admin two days after the last wave.

**7. Make the next attempt bounce.** Every repo now has rulesets that block force-pushes on the default branch, a shape-based scanner, a pre-push hook and a CI check that fails on a hit. Every repo also has instructions for AI agents: run the scan before any install, build, test or push, and if it fails, stop and tell a human. Don't fix it quietly.

## What it hit, and what it didn't

We have clients. This is the part they'd ask about, so here it is straight.

- **No client's production app ever built an attacker commit.** Every infected build on a client project was a preview build.
- **On most client projects, the preview builds had nothing worth stealing.** The real secrets (databases, payments, auth, API keys) were set for production only. What the infected previews could see was public URLs and IDs that already ship to every browser.
- **Where a preview build did hold a real secret, we treat it as stolen and rotate it.** We don't know that the malware read it. It ran with access to it, and that's enough.
- **Where it actually ran:** two of our own machines, Vercel preview builds, and production builds of one internal tool. That's the blast radius we know about, and it's the one we cleaned.

None of that was planned. We just happened to have scoped most secrets to production. It's the single reason this is an embarrassing story and not a client breach.

## What we learned

- **We had no idea where our keys were.** When we had to answer "which secrets could this build see?", we went project by project in Vercel, by hand. We found database credentials on a site that doesn't use a database. Keys nobody remembered adding. A GitHub Desktop token that was authorized once and never looked at again. Our key tracking was honestly terrible. Now every secret gets the narrowest environment it can live in, and we keep a list we can actually read.
- **Clean the history, not just the latest commit.** The payload is still in old commits. Merge, rebase or check out an old infected branch and it's back. That's how wave 1 came back after we "cleaned" it.
- **Half a cleanup is no cleanup.** One token we didn't revoke, one admin seat we didn't pull. Each time it was enough.
- **Check the shape of a file, not the strings in it.** Grepping for known strings missed variants. A config line over 2,000 characters, or code after a long run of blanks, caught all of them.
- **Test your scanner before you trust it.** Ours had never seen a path with a space in it, and it said "clean".
- **Block force-pushes on your default branches.** Repos with that ruleset came through the last wave untouched. GitHub Free doesn't offer rulesets on private repos, which is exactly where we got hit. If that's you, it's worth paying for the plan, or at least running the scanner in CI on every push.
- **Your AI follows the rules you write down.** The same agents that would have happily built the malware now refuse to. On November 6 one of them found the injected commits, stopped, and told us, instead of building or "fixing it quietly".

## Going deeper

The [full write-up](psa-long-writeup.md) has everything: how to tell if you're hit, the [indicators of compromise](psa-long-writeup.md#3-indicators-of-compromise), the [remediation checklist](psa-long-writeup.md#5-remediation-checklist) (the order matters), what we'd ask GitHub, Vercel and editor vendors to change, and every source.

## Credit

[OpenSourceMalware](https://github.com/OpenSourceMalware/PolinRider), [Socket](https://socket.dev/blog/polinrider-github-packagist), [SafeDep](https://safedep.io/astro-config-blockchain-c2-supply-chain/) and [Microsoft](https://microsoft.com/en-us/security/blog/2026/02/24/c2-developer-targeting-campaign) published the research that made this possible to untangle. We just added our part.

## Seen this?

Especially the GitHub Desktop variant, or commits where the committer time is exactly one hour behind the author's. Open an issue. We'd like to compare notes.
