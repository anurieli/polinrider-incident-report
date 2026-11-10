#!/usr/bin/env bash
# polinrider-hunter / scan_machine.sh -- READ-ONLY workstation check for the
# PolinRider / EtherHiding campaign (macOS first; partial Linux support).
#
# Checks:
#   * code-signature seal of Electron apps (GitHub Desktop, VS Code, Cursor,
#     Discord, Slack, ...) via `codesign --verify --deep --strict`
#   * hidden-tail / marker scan of those apps' JS (main.js, app.asar)
#   * leftover *.inz.orig / *.inz.cjs files (originals saved by the patcher)
#   * global npm package trees (found by path; npm/node are NEVER executed)
#   * Python startup hooks: *.pth with code, sitecustomize/usercustomize
#     (python3 is run only with -S -I so no .pth file executes)
#   * LaunchAgents/LaunchDaemons (macOS), autostart/systemd/cron (Linux)
#   * running `node -e` / `python -c` processes and known beacon strings
#   * global git hooks, shell rc files, editor settings & extensions
#   * optional --github: read-only `gh api` listing of force-pushes per repo
#
# Usage: scan_machine.sh [--no-self-test] [--all-apps] [--no-extensions]
#                        [--github] [--days N]
# Exit:  0 CLEAN, 1 INFECTED, 2 SUSPICIOUS, 3 scanner error / self-test failed

set -u
LC_ALL=C; export LC_ALL
T=$'\t'
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
SELF_DIR=$(cd "$SCRIPT_DIR/.." && pwd -P)
OS=$(uname -s)

DO_SELF_TEST=1; ALL_APPS=0; DO_EXT=1; DO_GH=0; DAYS=120
while [ $# -gt 0 ]; do
  case "$1" in
    --no-self-test)  DO_SELF_TEST=0 ;;
    --all-apps)      ALL_APPS=1 ;;
    --no-extensions) DO_EXT=0 ;;
    --github)        DO_GH=1 ;;
    --days)          shift; DAYS=${1:-120} ;;
    -h|--help)       sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 3 ;;
  esac
  shift
done
command -v perl >/dev/null 2>&1 || { echo "ERROR: perl not found" >&2; exit 3; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/polinrider-machine.XXXXXX") || exit 3
trap 'rm -rf "$TMP"' EXIT
F="$TMP/findings.tsv"; : > "$F"
add() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$F"; }

# Snapshot processes FIRST, before any perl process (whose -e script contains
# the marker strings) exists.
ps -axo pid=,ppid=,command= > "$TMP/ps.txt" 2>/dev/null || ps -eo pid=,ppid=,args= > "$TMP/ps.txt" 2>/dev/null

# --------------------------------------------------------------------------
# Content checker: file paths in @ARGV. Reports code hidden after a whitespace
# run and known marker strings. Large binaries are scanned in 8 MB chunks.
# --------------------------------------------------------------------------
read -r -d '' CHECK_PL <<'PERL'
use strict; use warnings;
use Cwd qw(abs_path);
my $SELF = $ENV{PR_SELF_DIR} || "\0none";
my $CTX  = $ENV{PR_CTX} || 'file';
my @C2 = qw(auth-confirm-eight.vercel.app default-configuration.vercel.app
  vscode-settings-bootstrap.vercel.app vscode-settings-config.vercel.app
  vscode-bootstrapper.vercel.app vscode-load-config.vercel.app 260120.vercel.app
  api-web3-auth.vercel.app price-oracle-v2.vercel.app oracle-v1-beta.vercel.app);
my @ADDR = qw(0x3b1574417524c11a7403c4b232CAcBb320CceBC6 0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a
  TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG);
my $C2RE = join '|', map { quotemeta } @C2;
my $ADRE = join '|', map { quotemeta } @ADDR;
my @STRONG = (
  [qr/['"]app-[A-Za-z0-9]+-eval['"]/,    "app-*-eval Electron implant marker"],
  [qr/global\s*\[\s*['"](?:!|_V)['"]\s*\]/, "global['!'] / global['_V'] loader marker"],
  [qr/A11-1369-4|A9-9259-1|A11--#/,      "campaign ID string"],
  [qr/rmcej%otb%|Cot%3t=shtP|_\$_1e42/,  "PolinRider decoder signature"],
  [qr/(?:$C2RE)/i,                       "known C2 domain"],
  [qr/(?:$ADRE)/i,                       "known blockchain dead-drop address"],
);
my %seen;
sub emit { my ($l,$c,$p,$d)=@_; $p =~ s/[\t\n]/ /g; return if $seen{"$l|$c|$p"}++; print "$l\t$c\t$p\t$d\n" }
for my $f (@ARGV) {
  next unless -f $f;
  my $ap = abs_path($f); $ap = $f unless defined $ap;
  next if index($ap, $SELF) == 0;
  open(my $fh, '<:raw', $f) or next;
  my ($buf, $carry) = ('', '');
  my $off = 0;
  while (read($fh, $buf, 8*1024*1024)) {
    my $s = $carry . $buf;
    if ($s =~ /[;)\]}'"\w]([ \t]{150,})[A-Za-z_\$(\[!;'"]/) {
      emit('SUSPICIOUS','hidden-tail', $f, "code continues after a run of ".length($1)." blanks ($CTX)");
    }
    for my $m (@STRONG) { emit('INFECTED','marker',$f,"$m->[1] ($CTX)") if $s =~ $m->[0] }
    $carry = substr($s, -512);
  }
  close $fh;
}
PERL

check_files() {  # stdin: NUL-separated paths; $1 = context label
  PR_SELF_DIR="$SELF_DIR" PR_CTX="$1" xargs -0 perl -e "$CHECK_PL" -- >> "$F"
}

find_inz() {  # $@ = roots
  local r
  for r in "$@"; do
    [ -e "$r" ] || continue
    find "$r" -maxdepth 8 \( -type d \( -name node_modules -o -name .git \) -prune \) -o -type f -name '*.inz.*' -print0 2>/dev/null
  done
}

# --------------------------------------------------------------------------
# Self-test: harmless canary "app" in a path with spaces
# --------------------------------------------------------------------------
self_test() {
  local base="$TMP/canary dir/Fake Electron App.app" out fail=0
  mkdir -p "$base/Contents/Resources/app"
  local m1="app-" m2="-eval"
  perl -e 'print "\x27use strict\x27;\n// line 2\n// line 3\nconst a=1;", " " x 400, "global[\x27e\x27]=\x27$ARGV[0]Canary$ARGV[1]\x27;/*harmless canary*/\n"' "$m1" "$m2" > "$base/Contents/Resources/app/main.js"
  : > "$base/Contents/Resources/app/main.js.inz.orig"
  out="$TMP/st.tsv"; : > "$out"
  find "$TMP/canary dir" -type f -name '*.js' -print0 | PR_SELF_DIR="$SELF_DIR" PR_CTX=selftest xargs -0 perl -e "$CHECK_PL" -- >> "$out"
  find_inz "$TMP/canary dir" | tr '\0' '\n' >> "$out"
  grep -F "INFECTED${T}marker${T}$base/Contents/Resources/app/main.js" "$out" >/dev/null || { echo "  self-test MISSED: Electron marker"; fail=1; }
  grep -F "SUSPICIOUS${T}hidden-tail${T}$base/Contents/Resources/app/main.js" "$out" >/dev/null || { echo "  self-test MISSED: hidden tail"; fail=1; }
  grep -F "main.js.inz.orig" "$out" >/dev/null || { echo "  self-test MISSED: .inz.orig leftover"; fail=1; }
  rm -rf "$TMP/canary dir"
  return $fail
}

echo "polinrider-hunter scan_machine.sh (read-only)  $(date -u '+%Y-%m-%dT%H:%M:%SZ')  os=$OS"
if [ "$DO_SELF_TEST" -eq 1 ]; then
  if self_test; then echo "self-test: PASS (canary app in a path with spaces detected)"
  else echo "self-test: FAIL - scanner not trustworthy here; do not rely on its results."; exit 3; fi
fi


# --------------------------------------------------------------------------
# 1. Electron / editor apps: code-signature seal + JS content
# --------------------------------------------------------------------------
NAMED_APPS="GitHub Desktop|Visual Studio Code|Visual Studio Code - Insiders|Cursor|Windsurf|VSCodium|Discord|Slack|Postman|Notion|Obsidian|Figma|Docker|1Password|Signal|WhatsApp|Claude|ChatGPT|Linear|Zed|Hyper|Warp|GitKraken|Fork|Sourcetree|Tower"

is_electron() { [ -d "$1/Contents/Frameworks/Electron Framework.framework" ]; }

check_app() {   # $1 = .app path
  local app="$1" name out rc
  name=$(basename "$app" .app)
  out=$(codesign --verify --deep --strict "$app" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then
    add INFO codesign "$app" "signature seal intact"
  elif printf '%s' "$out" | grep -qi 'not signed at all'; then
    add SUSPICIOUS codesign-unsigned "$app" "app is unsigned - cannot verify integrity; reinstall from the vendor if unsure"
  else
    add INFECTED codesign-broken "$app" "seal BROKEN: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-220) -> files inside the app were modified after signing (GitHub Desktop main.js patch looks exactly like this). Quit it, delete it, reinstall from the vendor, then rotate its tokens."
  fi
  # JS inside the bundle (main.js, out/main.js, app.asar ...)
  find "$app/Contents/Resources" -maxdepth 4 -type f \( -name '*.js' -o -name '*.cjs' -o -name '*.mjs' -o -name '*.asar' \) -size -400M -print0 2>/dev/null \
    | check_files "inside $name.app"
}

if [ "$OS" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then
  for dir in /Applications "$HOME/Applications"; do
    [ -d "$dir" ] || continue
    for app in "$dir"/*.app; do
      [ -d "$app" ] || continue
      name=$(basename "$app" .app)
      if [ "$ALL_APPS" -eq 1 ] || is_electron "$app" || printf '%s\n' "$name" | grep -Eqx "$NAMED_APPS"; then
        check_app "$app"
      fi
    done
  done
else
  # Linux: no codesign; scan typical Electron install locations for hidden tails/markers
  for d in /opt /usr/share /usr/lib "$HOME/.local/share" /snap; do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 5 -type f \( -path '*/resources/app/*.js' -o -path '*/resources/app/out/*.js' -o -name 'app.asar' \) -size -400M -print0 2>/dev/null \
      | check_files "Electron app ($d)"
  done
  add INFO codesign "-" "not macOS: verify editor/Electron packages with your package manager (e.g. 'dpkg -V', 'rpm -V') and reinstall if unsure"
fi

# --------------------------------------------------------------------------
# 2. Patcher leftovers (*.inz.orig, *.inz.cjs, ...)
# --------------------------------------------------------------------------
INZ_ROOTS=(/Applications "$HOME/Applications" "$HOME/Library/Application Support" "$HOME/.vscode" "$HOME/.cursor" "$HOME/.windsurf" "$HOME/.config" "$HOME/.local/share" /opt /usr/local/lib/node_modules /opt/homebrew/lib/node_modules)
while IFS= read -r -d '' f; do
  add INFECTED inz-leftover "$f" "original saved by the Electron/JS patcher (e.g. main.js.inz.orig) - the sibling file was modified"
done < <(find_inz "${INZ_ROOTS[@]}")

# --------------------------------------------------------------------------
# 3. Discord / per-user Electron module dirs
# --------------------------------------------------------------------------
for d in "$HOME/Library/Application Support/discord" "$HOME/.config/discord"; do
  [ -d "$d" ] && find "$d" -maxdepth 6 -type f -name 'index.js' -path '*discord_desktop_core*' -print0 2>/dev/null | check_files "Discord core module"
done

# --------------------------------------------------------------------------
# 4. Global npm trees (located by path; npm/node are never run)
# --------------------------------------------------------------------------
NPM_ROOTS=()
for r in /usr/local/lib/node_modules /opt/homebrew/lib/node_modules "$HOME/.npm-global/lib/node_modules" "$HOME/.local/lib/node_modules"; do
  [ -d "$r" ] && NPM_ROOTS+=("$r")
done
for r in "$HOME"/.nvm/versions/node/*/lib/node_modules "$HOME"/.volta/tools/image/node/*/lib/node_modules "$HOME"/.fnm/node-versions/*/installation/lib/node_modules; do
  [ -d "$r" ] && NPM_ROOTS+=("$r")
done
if command -v node >/dev/null 2>&1; then
  nb=$(command -v node); nr="$(cd "$(dirname "$nb")/.." 2>/dev/null && pwd -P)/lib/node_modules"
  [ -d "$nr" ] && NPM_ROOTS+=("$nr")
fi
if [ ${#NPM_ROOTS[@]} -gt 0 ]; then
  for r in "${NPM_ROOTS[@]}"; do
    find "$r" -maxdepth 5 -type f \( -name '*.js' -o -name '*.cjs' -o -name '*.mjs' \) -size -20M -print0 2>/dev/null | check_files "global npm ($r)"
    find "$r" -maxdepth 3 -name package.json -path '*/node_modules/*/package.json' -print0 2>/dev/null \
      | xargs -0 perl -ne 'if (/"(preinstall|install|postinstall)"\s*:\s*"([^"]*)"/) { print "INFO\tglobal-npm-install-script\t$ARGV\t$1: $2\n" }' >> "$F" 2>/dev/null
  done
else
  add INFO global-npm "-" "no global node_modules tree found in the usual locations"
fi

# --------------------------------------------------------------------------
# 5. Python startup hooks (python3 run with -S -I: no site, no .pth executed)
# --------------------------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
  python3 -S -I -c 'import site,sys
paths=set()
try:
  paths.update(site.getsitepackages())
except Exception: pass
try:
  paths.add(site.getusersitepackages())
except Exception: pass
for p in sorted(paths): sys.stdout.write(p+"\0")' 2>/dev/null > "$TMP/pydirs"
  while IFS= read -r -d '' sp; do
    [ -d "$sp" ] || continue
    find "$sp" -maxdepth 1 -type f -name '*.pth' -print0 2>/dev/null | xargs -0 perl -ne '
      next unless /^\s*import[\s;]/;
      my $l = $_; chomp $l; $l = substr($l, 0, 160);
      if (/exec\s*\(|eval\s*\(|base64|b64decode|urllib|requests|socket|subprocess|http[s]?:\/\/|__import__\(\s*["\x27](?:os|subprocess)/) {
        print "SUSPICIOUS\tpython-pth\t$ARGV\texecutable .pth line runs at every Python start: $l\n";
      } else {
        print "INFO\tpython-pth\t$ARGV\texecutable .pth line (common for setuptools/venv tools): $l\n";
      }' >> "$F" 2>/dev/null
    for cust in sitecustomize.py usercustomize.py; do
      [ -f "$sp/$cust" ] && add SUSPICIOUS python-customize "$sp/$cust" "runs at every Python start - review contents"
    done
  done < "$TMP/pydirs"
fi

# --------------------------------------------------------------------------
# 6. Persistence: LaunchAgents/Daemons (macOS), autostart/systemd/cron (Linux)
# --------------------------------------------------------------------------
if [ "$OS" = "Darwin" ]; then
  for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
    [ -d "$d" ] || continue
    for p in "$d"/*.plist; do
      [ -f "$p" ] || continue
      prog=$(plutil -convert xml1 -o - "$p" 2>/dev/null | perl -0ne '
        my ($pa) = /<key>ProgramArguments<\/key>\s*<array>(.*?)<\/array>/s;
        my ($pg) = /<key>Program<\/key>\s*<string>(.*?)<\/string>/s;
        my @a = defined $pa ? ($pa =~ /<string>(.*?)<\/string>/gs) : ();
        unshift @a, $pg if defined $pg;
        print join(" ", @a);')
      prog=$(printf '%s' "$prog" | tr '\t\n' '  ' | cut -c1-300)
      if printf '%s' "$prog" | grep -Eq 'app-[A-Za-z0-9]+-eval|vercel\.app|_t_s|verify-human|/0x/(js|clb)'; then
        add INFECTED launch-item "$p" "runs: $prog"
      elif printf '%s' "$prog" | grep -Eq '(^|[ /])(node|python[0-9.]*|osascript)( |$)| -c | -e |curl |wget |base64|/tmp/|/private/tmp/|/Users/Shared/' \
           || printf '%s' "${prog%% *}" | grep -Eq '/\.[A-Za-z0-9_-]+/'; then
        add SUSPICIOUS launch-item "$p" "runs an interpreter/inline/hidden-path command: $prog"
      else
        case "$(basename "$p")" in com.apple.*) ;; *) add INFO launch-item "$p" "runs: $prog" ;; esac
      fi
    done
  done
else
  for d in "$HOME/.config/autostart" "$HOME/.config/systemd/user"; do
    [ -d "$d" ] && find "$d" -maxdepth 2 -type f -print0 2>/dev/null | xargs -0 perl -ne '
      if (/^(?:Exec|ExecStart)=(.*)/) { my $c=$1; my $lvl = ($c =~ /\bnode\b|python[0-9.]*\s+-c|\s-e\s|curl|wget|base64|\/tmp\//) ? "SUSPICIOUS" : "INFO"; print "$lvl\tautostart\t$ARGV\truns: $c\n" }' >> "$F" 2>/dev/null
  done
  if command -v crontab >/dev/null 2>&1; then
    crontab -l 2>/dev/null | grep -v '^\s*#' | grep -E '\bnode\b|python[0-9.]* +-c|curl|wget|base64' | while IFS= read -r l; do add SUSPICIOUS crontab "user crontab" "$l"; done
  fi
fi

# --------------------------------------------------------------------------
# 7. Running processes (snapshot taken at start)
# --------------------------------------------------------------------------
export PR_MYPID=$$
perl -ne '
  my ($pid, $ppid, $cmd) = /^\s*(\d+)\s+(\d+)\s+(.*)$/ or next;
  next if $pid == $ENV{PR_MYPID};
  next if $cmd =~ /polinrider|^\s*ps\s/;
  my $short = substr($cmd, 0, 200);
  if ($cmd =~ /_t_s|verify-human|\/0x\/clb|\/0x\/js|app-[A-Za-z0-9]+-eval|vercel\.app\/api/) {
    print "INFECTED\tprocess\tpid $pid\tbeacon-like process: $short\n";
  } elsif ($cmd =~ /(?:^|\/)node(?:\.exe)?\s+(?:-e|--eval|-p)\s/) {
    print "SUSPICIOUS\tprocess\tpid $pid\tnode -e process (the beacon runs as node -e): $short\n";
  } elsif ($cmd =~ /python[0-9.]*\s+-c\s.*(?:base64|exec\(|urllib|socket)/) {
    print "SUSPICIOUS\tprocess\tpid $pid\tinline python with decode/network: $short\n";
  }' < "$TMP/ps.txt" >> "$F" 2>/dev/null

# --------------------------------------------------------------------------
# 8. Global git hooks / templates, shell rc files, editor user settings
# --------------------------------------------------------------------------
if command -v git >/dev/null 2>&1; then
  for k in core.hooksPath init.templateDir; do
    v=$(git config --global --get "$k" 2>/dev/null)
    if [ -n "$v" ]; then
      v="${v/#\~/$HOME}"
      add INFO "git-global-$k" "$v" "global $k is set - every repo uses hooks from here; review them"
      [ -d "$v" ] && find "$v" -type f ! -name '*.sample' -print0 2>/dev/null | check_files "global git hooks"
    fi
  done
fi
for rc in .zshrc .zshenv .zprofile .bashrc .bash_profile .profile .config/fish/config.fish; do
  f="$HOME/$rc"; [ -f "$f" ] || continue
  printf '%s\0' "$f" | check_files "shell startup file"
  perl -ne 'print "SUSPICIOUS\tshell-rc\t$ARGV:$.\tstartup line runs inline/remote code: ".substr($_,0,160) if /node\s+-e\s|curl[^|]*\|\s*(ba|z)?sh|wget[^|]*\|\s*(ba|z)?sh|base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh/' "$f" >> "$F" 2>/dev/null
done
for s in "$HOME/Library/Application Support/Code/User/settings.json" "$HOME/Library/Application Support/Cursor/User/settings.json" \
         "$HOME/Library/Application Support/Windsurf/User/settings.json" "$HOME/.config/Code/User/settings.json" "$HOME/.config/Cursor/User/settings.json"; do
  [ -f "$s" ] || continue
  grep -Eq '"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*(true|"on")' "$s" && add SUSPICIOUS editor-auto-tasks "$s" "automatic folderOpen tasks allowed globally - set to \"off\""
  grep -Eq '"security\.workspace\.trust\.enabled"[[:space:]]*:[[:space:]]*false' "$s" && add SUSPICIOUS editor-trust-off "$s" "Workspace Trust disabled globally"
done
[ -f "$HOME/.config/gh/hosts.yml" ] && add INFO gh-token-on-disk "$HOME/.config/gh/hosts.yml" "GitHub CLI token stored here (contents not read) - rotate with 'gh auth logout' + re-login from a clean machine if compromised"

# --------------------------------------------------------------------------
# 9. Editor extensions (hidden tails / markers)
# --------------------------------------------------------------------------
if [ "$DO_EXT" -eq 1 ]; then
  for e in "$HOME/.vscode/extensions" "$HOME/.vscode-insiders/extensions" "$HOME/.cursor/extensions" "$HOME/.windsurf/extensions" "$HOME/.vscode-oss/extensions"; do
    [ -d "$e" ] && find "$e" -maxdepth 5 \( -type d -name node_modules -prune \) -o -type f \( -name '*.js' -o -name '*.cjs' -o -name '*.mjs' \) -size -20M -print0 2>/dev/null | check_files "editor extension"
  done
fi

# --------------------------------------------------------------------------
# 10. Optional: GitHub force-push activity (read-only gh api calls)
# --------------------------------------------------------------------------
if [ "$DO_GH" -eq 1 ]; then
  if ! command -v gh >/dev/null 2>&1; then
    add INFO github "-" "gh not installed - check https://github.com/settings/applications, /settings/tokens, /settings/keys and /settings/security-log manually"
  elif ! gh auth status >/dev/null 2>&1; then
    add INFO github "-" "gh not authenticated - skipped"
  else
    since=$(perl -e 'my @t=gmtime(time - $ARGV[0]*86400); printf "%04d-%02d-%02dT00:00:00Z", $t[5]+1900,$t[4]+1,$t[3]' "$DAYS")
    me=$(gh api user -q .login 2>/dev/null)
    { gh repo list "$me" --limit 500 --json nameWithOwner -q '.[].nameWithOwner' 2>/dev/null
      for o in $(gh api user/orgs -q '.[].login' 2>/dev/null); do gh repo list "$o" --limit 500 --json nameWithOwner -q '.[].nameWithOwner' 2>/dev/null; done
    } | sort -u > "$TMP/repos.txt"
    nrepos=$(wc -l < "$TMP/repos.txt" | tr -d ' ')
    add INFO github "$me" "checking force-push activity since $since across $nrepos repos"
    while IFS= read -r r; do
      [ -n "$r" ] || continue
      gh api "repos/$r/activity?activity_type=force_push&per_page=100" \
        -q ".[] | select(.timestamp >= \"$since\") | [.timestamp, .actor.login, .ref, .before, .after] | @tsv" 2>/dev/null \
        | while IFS="$T" read -r ts actor ref before after; do
            add SUSPICIOUS github-force-push "$r $ref" "$ts by $actor  before=$before after=$after  (restore with the 'before' SHA if this was not you)"
          done
    done < "$TMP/repos.txt"
    gh api user/keys -q '.[] | [.id, .title, .created_at] | @tsv' 2>/dev/null | while IFS="$T" read -r id title created; do
      add INFO github-ssh-key "$me" "SSH key id=$id title=\"$title\" created=$created - remove any you do not recognise"
    done
    add INFO github-manual "-" "OAuth apps / GitHub App authorizations / PATs cannot be fully listed via API: review https://github.com/settings/applications , https://github.com/settings/tokens , https://github.com/settings/security-log"
  fi
fi

n_inf=$(grep -c '^INFECTED' "$F" | tr -d ' '); n_sus=$(grep -c '^SUSPICIOUS' "$F" | tr -d ' ')
echo
for lvl in INFECTED SUSPICIOUS INFO; do
  if grep -q "^$lvl" "$F"; then
    echo "== $lvl =="
    grep "^$lvl" "$F" | sort -u | awk -F '\t' '{ printf "[%s] %-24s %s\n      %s\n", $1, $2, $3, $4 }'
    echo
  fi
done
if [ "${n_inf:-0}" -gt 0 ]; then
  echo "RESULT: INFECTED ($n_inf infected, $n_sus suspicious)"
  echo "Treat every credential this machine could reach as stolen. Rotate from a DIFFERENT, clean machine."
  exit 1
elif [ "${n_sus:-0}" -gt 0 ]; then
  echo "RESULT: SUSPICIOUS ($n_sus finding(s) need human review)"; exit 2
else
  echo "RESULT: CLEAN (no findings)"; exit 0
fi
