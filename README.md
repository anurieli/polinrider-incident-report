# We got hacked by the space bar

*North Korea's PolinRider campaign put malware in about 60 of our repos, under our own names. Here's how to check if it's in yours, and what to do if it is.*

*By Ariel Nurieli. The cleanup was engineered by Adi Alia ([@Adialia1](https://github.com/Adialia1)).*

---

## What happened

In August one of our engineers was moving fast on a build, and his AI agent found a project on the internet. It either picked it on its own or recommended it, and nobody really cared. We just went with it. He built it on his Mac. That one build patched the GitHub Desktop app and handed someone a token that could act as us.

From then on they rewrote our real commits (same names, same dates, same messages) and added one thing: a line of malware at the end of a config file nobody opens, like `postcss.config.mjs`, hidden behind about 300 blank spaces so it sits off the edge of the screen. You could open the file and see nothing.

It came back four times, because we kept doing half the job:

| When (UTC) | What |
|---|---|
| ~Aug 18 to 20 | One infected build on a Mac. GitHub Desktop gets patched. |
| Sep 1 | Wave 1. Malicious pushes to many repos. We clean up Sep 2. |
| Oct 19 to 21 | Wave 2, pushed from a Windows machine. |
| Nov 2 | Wave 3. Force-pushes across about 60 repos in 4 orgs and accounts. |
| Nov 6, 22:48 to 23:11 | Wave 4. 153 force-pushes in 23 minutes. Vercel builds the malware 32 times. |

Then our scanner said the Mac was clean. It had choked on the space in `GitHub Desktop.app`. 300 spaces hid the malware. One space hid the infected app.

## Are you hit? Check in 30 seconds

**Read before you run.** You're reading a warning about random repos, on a random repo. Everything here is short, plain text and read-only.

From the folder that holds your projects:

```bash
find . -type f -name "*.config.*" -not -path "*/node_modules/*" -exec awk 'length($0)>2000{print FILENAME; nextfile}' {} +
```

No output is what you want. If it prints a file: **don't build, don't `npm install`, and don't open that folder in VS Code or Cursor** (one variant runs when the folder opens). Look at the file from the terminal.

On a Mac, also run this. Any error means the app was modified:

```bash
codesign --verify --deep --strict "/Applications/GitHub Desktop.app"
```

That covers the most common variants. Other signs:
- `package.json` scripts rewritten to `node api.js && next build` or `node init && next dev`
- `.vscode/tasks.json` with a `runOn: folderOpen` task that runs a "font" file
- `.gitignore` suddenly no longer ignoring `.env` or `.vscode`
- Commits that look like yours but whose committer time zone isn't yours: `git log --format='%h %aI %cI %an | %cn'`

**Easiest full check: let your AI coding tool do it.** Open [`detect-prompt.md`](detect-prompt.md), copy the block, and paste it into Claude Code, Cursor or Codex. It audits your machine and repos read-only, reports INFECTED / SUSPICIOUS / CLEAN, and asks before it changes anything. Read it first. It's one page of plain text.

| Tool | What it does |
|---|---|
| [`detect-prompt.md`](detect-prompt.md) | The copy-paste prompt above. |
| [`skill/polinrider-hunter`](skill/polinrider-hunter/SKILL.md) | A Claude Code skill with two scanners, one for repos and one for the machine. Each tests itself on a path with spaces first. |

## If you're hit: fix it in this order

Order matters. Rotate keys while something is still infected and you hand over the new ones too.

1. **Stop building.** Pause auto-deploys (Vercel, Netlify, CI) on affected projects.
2. **Clean the machine.** Reinstall any app that fails `codesign`, from the vendor. Look for `*.inz.orig` files and `node -e` processes.
3. **Revoke everything, from a clean machine.** Every GitHub OAuth app, personal token and SSH key, in every account and org. Remove admin from any account that was used against you until its machine is clean.
4. **Restore branches exactly.** `gh api "repos/OWNER/REPO/activity?activity_type=force_push"` lists the before and after commit of every force-push. Scan the "before" commit, then reset to it.
5. **Rotate the secrets every infected build could see.** Check which environment each infected build ran in. A preview build sees preview variables only.
6. **Block force-pushes** on your default branches with a GitHub ruleset, and add the scanner as a pre-push hook and a CI check.

Every step, with commands: [full write-up](psa-long-writeup.md#5-remediation-checklist).

## What it costs you

- **Every secret the infected machine could reach.** Git tokens, cloud CLIs, `.env` files, browser sessions.
- **Every environment variable of every project that built an infected commit.** Assume all of them are stolen.
- **Your team, CI and clients.** Every infected branch re-infects whoever builds it next: a teammate's laptop, a CI runner, Vercel.
- **It comes back.** The payload stays in your git history. Merge or check out an old branch and it returns. One token you forgot to revoke is enough for a new wave.

## What it hit for us

We have clients, so we checked this first.

**The last wave, and the biggest one, never reached production.** Not on a client's app, and not on our own products. On November 6 every infected build was a preview, because of safeguards we'd put in place for exactly this kind of day:
- Our main branches block force-pushes, so the attacker could only rewrite side branches.
- Production only ships from main, and every push runs the scanner in CI.
- The real secrets (databases, payments, auth, API keys) only exist in production. The infected previews could see public URLs and IDs and not much else. Where a preview did hold a real secret, we treat it as stolen and are rotating it.

The earlier waves are a different story. In September and October, before those safeguards existed, the malware did land on our main branches, and production builds ran while it was there. So for every project hit then, we treat the production secrets as exposed too.

It was still a close one. We had no real record of where all our keys lived. Answering "what could this build see?" meant going through Vercel project by project, by hand. We found database credentials on a site that doesn't use a database, and a GitHub Desktop token that was authorized once and never looked at again. We're fixing that: every secret scoped as narrowly as it can be, and one list of where they all live.

And it's on us. We didn't put enough safeguards around what our engineers' agents were allowed to pull in. That's the trade everyone building with AI is making right now, between moving fast and moving properly. You can take that risk, as long as you have good systems underneath it.

## The lesson

We all pull code from strangers now, all day. A repo from a tweet. A starter template. A package somebody's agent suggested. More and more, we're not even the one choosing. Your AI picks it, installs it, builds it. Your AI has no idea who wrote that repo, and it will run it on the machine that holds all your keys.

If you're vibe coding, or letting agents run things you don't fully understand: run routine checks, and talk to someone who knows how to build systems that hold up against this. The attackers are using the same tools we are.

Know what you're running. Especially when you didn't pick it.

One thing that worked: we wrote instructions into every repo telling our AI agents to run the scanner before any install, build or push, and to stop and tell a human if it fails. On November 6 an agent found the injected commits, stopped and told us, instead of building them.

---

**Going deeper:** the [full write-up](psa-long-writeup.md) has every indicator, the full remediation checklist, and what we'd ask GitHub, Vercel and editor makers to change.

**Credit:** Adi Alia ([@Adialia1](https://github.com/Adialia1)) is the engineer who traced every push, restored every branch and built the scanners in this repo. [OpenSourceMalware](https://github.com/OpenSourceMalware/PolinRider), [Socket](https://socket.dev/blog/polinrider-github-packagist), [SafeDep](https://safedep.io/astro-config-blockchain-c2-supply-chain/) and [Microsoft](https://microsoft.com/en-us/security/blog/2026/02/24/c2-developer-targeting-campaign) did the public research that made it possible to untangle.

**Seen this?** Especially the GitHub Desktop variant, or commits whose committer time is exactly one hour behind the author's. [Open an issue](../../issues). We'd like to compare notes.
