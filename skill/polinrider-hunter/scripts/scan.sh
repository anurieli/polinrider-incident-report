#!/usr/bin/env bash
# polinrider-hunter / scan.sh  --  READ-ONLY repository scanner for the
# PolinRider / EtherHiding build-config injection campaign.
#
# What it does (never modifies anything it scans):
#   * shape-based checks on working-tree files (long lines, code hidden after a
#     whitespace run, fake fonts, folderOpen tasks, rewritten package.json
#     scripts, base64 C2 in .env, .gitignore hiding pusher tooling, ...)
#   * the same content checks on every local and remote-tracking branch tip,
#     read straight from git objects (no checkout, no fetch)
#   * commit-fingerprint checks (re-committed commits whose committer identity
#     or timezone does not match the author)
#   * a self-test canary (in a temp dir whose path contains spaces) that must
#     be detected before any real result is trusted
#
# Never runs npm / node / python / builds. Needs only bash, find, xargs, perl
# and (optionally) git. Compatible with macOS bash 3.2.
#
# Usage: scan.sh [--no-self-test] [--no-git] [--deps] [--max-commits N] [PATH ...]
# Exit:  0 CLEAN, 1 INFECTED, 2 SUSPICIOUS (review), 3 scanner error / self-test failed

set -u
LC_ALL=C; export LC_ALL
T=$'\t'

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
SELF_DIR=$(cd "$SCRIPT_DIR/.." && pwd -P)

DO_SELF_TEST=1
DO_GIT=1
INCLUDE_DEPS=0
MAX_COMMITS=5000
ROOTS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --no-self-test) DO_SELF_TEST=0 ;;
    --no-git)       DO_GIT=0 ;;
    --deps)         INCLUDE_DEPS=1 ;;
    --max-commits)  shift; MAX_COMMITS=${1:-5000} ;;
    -h|--help)      sed -n '2,22p' "$0"; exit 0 ;;
    --) shift; while [ $# -gt 0 ]; do ROOTS+=("$1"); shift; done; break ;;
    -*) echo "unknown option: $1" >&2; exit 3 ;;
    *)  ROOTS+=("$1") ;;
  esac
  shift
done
[ ${#ROOTS[@]} -eq 0 ] && ROOTS=(".")

for bin in perl find xargs; do
  command -v "$bin" >/dev/null 2>&1 || { echo "ERROR: $bin not found" >&2; exit 3; }
done
HAVE_GIT=0; command -v git >/dev/null 2>&1 && HAVE_GIT=1

TMP=$(mktemp -d "${TMPDIR:-/tmp}/polinrider-scan.XXXXXX") || exit 3
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------------------
# Detector (perl). Modes:
#   PR_MODE=files : file paths in @ARGV (from find -print0 | xargs -0)
#   PR_MODE=git   : PR_REPO=<repo>; scans blobs at every branch tip, commit
#                   fingerprints, and history of pusher-tool files
# Output lines: LEVEL \t CHECK \t LOCATION \t DETAIL
# ---------------------------------------------------------------------------
read -r -d '' DETECT_PL <<'PERL'
use strict; use warnings;
use Cwd qw(abs_path);
use IPC::Open2;
use IO::Handle;
use MIME::Base64 qw(decode_base64);

my $SELF = $ENV{PR_SELF_DIR} || "\0none";
my $MAXREAD = 10*1024*1024;

my @C2 = qw(auth-confirm-eight.vercel.app default-configuration.vercel.app
  vscode-settings-bootstrap.vercel.app vscode-settings-config.vercel.app
  vscode-bootstrapper.vercel.app vscode-load-config.vercel.app 260120.vercel.app
  api-web3-auth.vercel.app price-oracle-v2.vercel.app oracle-v1-beta.vercel.app);
my @ADDR = qw(0x3b1574417524c11a7403c4b232CAcBb320CceBC6
  0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a
  TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG);
my $C2RE   = join '|', map { quotemeta } @C2;
my $ADDRRE = join '|', map { quotemeta } @ADDR;
my @STRONG = (
  [qr/global\s*\[\s*['"]!['"]\s*\]\s*=/,          "global['!'] loader marker"],
  [qr/global\s*\[\s*['"]_V['"]\s*\]/,             "global['_V'] loader marker"],
  [qr/['"]app-[A-Za-z0-9]+-eval['"]/,             "app-*-eval Electron implant marker"],
  [qr/A11-1369-4|A9-9259-1|A11--#/,               "campaign ID string"],
  [qr/rmcej%otb%|Cot%3t=shtP|_\$_1e42/,           "PolinRider decoder signature"],
  [qr/(?:$C2RE)/i,                                "known C2 domain"],
  [qr/(?:$ADDRRE)/i,                              "known blockchain dead-drop address"],
);
my @WEAK = (
  [qr/verify-human/,        "verify-human string"],
  [qr{/0x/(?:js|clb)\b},    "/0x/js or /0x/clb path"],
  [qr/\b_t_s\b/,            "_t_s identifier"],
);

my %seen;
sub emit {
  my ($lvl,$chk,$loc,$det) = @_;
  $det =~ s/[\t\r\n]/ /g; $loc =~ s/[\t\r\n]/ /g;
  return if $seen{"$lvl|$chk|$loc"}++;
  print "$lvl\t$chk\t$loc\t$det\n";
}

sub base { my $p = shift; return $p =~ m{([^/]+)$} ? $1 : $p }

sub is_config {
  my $n = shift;
  return 1 if $n =~ /\.config\.[cm]?[jt]sx?$/i;
  return 1 if $n =~ /^\.[\w-]+rc\.[cm]?js$/;
  return 1 if $n =~ /^gatsby-(?:config|node|browser|ssr)\.[jt]sx?$/;
  return 0;
}
sub is_code {
  my ($n,$p) = @_;
  return 1 if $n =~ /\.(?:[cm]?[jt]sx?|json|py|php|bat|cmd|ps1|sh|vue|svelte)$/i;
  return 1 if $n eq 'init';
  return 1 if $p =~ m{(?:^|/)\.git/hooks/[^/]+$} && $n !~ /\.sample$/;
  return 0;
}
sub is_font { return $_[0] =~ /\.(?:woff2?|ttf|otf|eot|lkf|orc)$/i }

sub printable_ratio {
  my $s = substr($_[0], 0, 4096);
  return 0 unless length $s;
  my $p = ($s =~ tr/\x20-\x7e\t\r\n//);
  return $p / length($s);
}

# check_content(location, path, data, root_level_flag)
sub check_content {
  my ($loc, $path, $data, $rootlvl) = @_;
  my $n = base($path);
  my $cfg  = is_config($n);
  my $code = is_code($n, $path);

  # ---- line-shape checks (primary signal) -----------------------------------
  if ($cfg || $code) {
    my $ln = 0;
    for my $line (split /\n/, $data) {
      $ln++;
      my $len = length $line;
      if ($line =~ /\S([ \t]{150,})\S/) {
        my $pad  = length $1;
        my $tail = $len - $-[1] - $pad;
        if ($cfg || $tail > 1000) {
          emit('INFECTED','hidden-tail',"$loc:$ln","code after a run of $pad blanks ($tail chars hidden off-screen; line is $len chars)");
        } else {
          emit('SUSPICIOUS','hidden-tail',"$loc:$ln","text after a run of $pad blanks ($tail chars)");
        }
      }
      if ($cfg && $len > 2000) {
        emit('INFECTED','config-long-line',"$loc:$ln","build config line is $len chars (clean configs are tiny)");
      }
      if ($n =~ /^(?:api\.js|init|init\.js)$/ && $rootlvl && $len > 2000) {
        emit('INFECTED','root-loader-long-line',"$loc:$ln","root $n has a $len-char line");
      }
    }
  }

  # ---- build configs --------------------------------------------------------
  if ($cfg) {
    if (substr($data,0,400) =~ /import\s*\{\s*createRequire\s*\}\s*from\s*['"](?:node:)?module['"]/) {
      emit('SUSPICIOUS','createRequire-shim',$loc,"createRequire shim at top of config (often prepended by the injector; legit uses exist)");
    }
    if ($n =~ /^next\.config\./ && $data =~ /atob\s*\(\s*process\.env/) {
      emit('INFECTED','nextconfig-env-loader',$loc,"next.config decodes a URL from process.env (atob -> fetch -> eval pattern)");
    } elsif ($data =~ /\beval\s*\(|new\s+Function\s*\(/) {
      emit('SUSPICIOUS','config-eval',$loc,"build config calls eval/new Function");
    }
    if ($data =~ /['"]node-fetch['"]/ && $data =~ /process\.env/ && $data =~ /\beval\s*\(|new\s+Function/) {
      emit('INFECTED','config-fetch-eval',$loc,"config fetches a URL taken from env and evaluates the response");
    }
  }

  # ---- package.json ---------------------------------------------------------
  if ($n eq 'package.json') {
    while ($data =~ /"([\w:.-]+)"\s*:\s*"((?:[^"\\]|\\.)*)"/g) {
      my ($k,$v) = ($1,$2);
      next unless $k =~ /^(?:pre|post)?(?:dev|build|start|test|prepare|install|serve|lint)$/;
      if ($v =~ /\bnode\s+(?:\.\/)?(api(?:\.js)?|init(?:\.js)?|[^\s&;|]*\.(?:woff2?|lkf|orc|ttf|otf))\s*(?:&&|;|\|\||$)/) {
        emit('INFECTED','pkg-script-loader',$loc,"script \"$k\" runs \"node $1\" before the real command: $v");
      } elsif ($v =~ /\bnode\s+(?:-e|--eval|-p)\b/) {
        emit('SUSPICIOUS','pkg-script-eval',$loc,"script \"$k\" uses node -e: $v");
      } elsif ($v =~ /\bnode\s+([^\s&;|-][^\s&;|]*)\s*&&\s*(?:next|vite|vitest|jest|react-scripts|nuxt|astro|webpack|expo)\b/) {
        emit('SUSPICIOUS','pkg-script-prefix',$loc,"script \"$k\" runs \"node $1\" before the build/dev command (verify what it is): $v");
      }
    }
    if ($data =~ /"dotenv"\s*:\s*"\^8\.2\.0"/ && $data =~ /"node-fetch"\s*:\s*"\^3\.3\.2"/) {
      emit('SUSPICIOUS','pkg-deps-pair',$loc,"dotenv ^8.2.0 + node-fetch ^3.3.2 both present (pair added by the next.config variant)");
    }
  }

  # ---- root loader files ----------------------------------------------------
  if ($n =~ /^(?:api\.js|init|init\.js)$/ && $rootlvl) {
    if ($data =~ /\beval\s*\(|new\s+Function|child_process|atob\s*\(|['"]base64['"]/) {
      emit('SUSPICIOUS','root-loader',$loc,"root $n next to package.json uses eval/child_process/base64 - check package.json scripts");
    }
  }

  # ---- VS Code workspace ----------------------------------------------------
  if ($path =~ m{(?:^|/)\.vscode/tasks\.json$} && $data =~ /folderOpen/) {
    if ($data =~ /\.(?:woff2?|lkf|orc|ttf|otf)\b|fonts\/|\bcurl\s|\bwget\s|vercel\.app|node\s+-e|\|\s*(?:ba|z)?sh\b|powershell|\biex\b|Invoke-WebRequest/i) {
      emit('INFECTED','vscode-folderOpen-task',$loc,"task auto-runs on folder open and executes a font/remote/inline payload");
    } else {
      emit('SUSPICIOUS','vscode-folderOpen-task',$loc,"task with runOn: folderOpen (runs when the folder is opened) - review it");
    }
  }
  if ($path =~ m{(?:^|/)\.vscode/settings\.json$}) {
    emit('SUSPICIOUS','vscode-auto-tasks',$loc,"task.allowAutomaticTasks enabled in workspace settings")
      if $data =~ /"task\.allowAutomaticTasks"\s*:\s*(?:true|"on")/;
    emit('SUSPICIOUS','vscode-trust-off',$loc,"workspace trust disabled")
      if $data =~ /"security\.workspace\.trust\.enabled"\s*:\s*false/;
  }

  # ---- fake fonts -----------------------------------------------------------
  if (is_font($n) && length $data) {
    my $h = substr($data,0,4);
    my $ok = ($h eq 'wOFF' || $h eq 'wOF2' || $h eq "\x00\x01\x00\x00" || $h eq 'OTTO'
              || $h eq 'true' || $h eq 'typ1' || $h eq 'ttcf'
              || (length($data) > 36 && substr($data,34,2) eq 'LP'));
    my $pr = printable_ratio($data);
    if ($n =~ /\.(?:lkf|orc)$/i) {
      if ($pr > 0.9) { emit('INFECTED','fake-font',$loc,"font-named .lkf/.orc file is plain text/JS") }
      else           { emit('SUSPICIOUS','fake-font',$loc,"unusual .lkf/.orc file in a web project") }
    } elsif (!$ok) {
      if ($pr > 0.85) { emit('INFECTED','fake-font',$loc,"\"font\" has no font header and is plain text (JS disguised as a font)") }
      else            { emit('SUSPICIOUS','fake-font',$loc,"font file has an invalid header") }
    }
  }

  # ---- .env (never prints values; only the decoded host) ---------------------
  if ($n =~ /^\.env/) {
    my $ln = 0;
    for my $line (split /\n/, $data) {
      $ln++;
      next unless $line =~ /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?(aHR0c[A-Za-z0-9+\/=_-]{8,})/;
      my ($k,$v) = ($1,$2);
      (my $vv = $v) =~ tr{-_}{+/};
      my $dec = decode_base64($vv);
      my $host = ($dec =~ m{^https?://([^/\s:?#]+)}) ? $1 : '?';
      if ($host =~ /^(?:$C2RE)$/i) {
        emit('INFECTED','env-c2',"$loc:$ln","$k is base64 of a known C2 URL (host $host)");
      } elsif ($k eq 'AUTH_API_KEY') {
        emit('INFECTED','env-c2',"$loc:$ln","AUTH_API_KEY holds a base64-encoded URL (host $host) - matches the next.config loader variant");
      } else {
        emit('SUSPICIOUS','env-b64-url',"$loc:$ln","$k holds a base64-encoded URL (host $host)");
      }
    }
  }

  # ---- .gitignore hiding pusher tooling --------------------------------------
  if ($n eq '.gitignore') {
    for my $l (split /\n/, $data) {
      $l =~ s/^\s+|\s+$//g;
      if ($l =~ m{^/?(?:temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json)$}) {
        emit('INFECTED','gitignore-pusher',$loc,".gitignore hides attacker pusher tooling: $l");
      } elsif ($l =~ m{^/?config\.bat$}) {
        emit('SUSPICIOUS','gitignore-pusher',$loc,".gitignore lists config.bat (seen with the Windows pusher)");
      }
    }
  }

  # ---- pusher tooling files themselves --------------------------------------
  if ($n =~ /^temp_(?:auto|interactive)_push\.bat$/i) {
    emit('INFECTED','pusher-file',$loc,"attacker force-push tooling file present");
  } elsif ($n eq 'branch_structure.json' || $n eq 'config.bat') {
    emit('SUSPICIOUS','pusher-file',$loc,"file name matches Windows pusher tooling ($n)");
  }

  # ---- python variant -------------------------------------------------------
  if ($n =~ /\.py$/) {
    if ($path =~ m{(?:^|/)utils/transport\.py$}) {
      if ($data =~ /\b(?:exec|eval)\s*\(/ && $data =~ /base64|web3|eth_|0x[0-9a-fA-F]{40}|rpc/i) {
        emit('INFECTED','py-transport',$loc,"utils/transport.py evaluates decoded/remote content (Python variant)");
      } else {
        emit('SUSPICIOUS','py-transport',$loc,"utils/transport.py present - compare with your own history");
      }
    }
    if ($data =~ /\bexec\s*\([^\n]*(?:b64decode|base64|\.decode\s*\()/) {
      emit('SUSPICIOUS','py-exec-decode',$loc,"Python evaluates decoded data");
    }
  }

  # ---- marker strings (bonus signal; shape checks above are primary) --------
  if ($code) {
    my $hit = 0;
    for my $m (@STRONG) { if ($data =~ $m->[0]) { emit('INFECTED','marker',$loc,$m->[1]); $hit = 1 } }
    unless ($hit) { for my $m (@WEAK) { emit('SUSPICIOUS','marker',$loc,$m->[1]) if $data =~ $m->[0] } }
  }
}

sub read_file {
  my $f = shift;
  open(my $fh, '<:raw', $f) or return undef;
  my $d = ''; read($fh, $d, $MAXREAD); close $fh; return $d;
}

my $mode = $ENV{PR_MODE} || 'files';

if ($mode eq 'files') {
  for my $f (@ARGV) {
    next unless -f $f;
    my $ap = abs_path($f); $ap = $f unless defined $ap;
    next if index($ap, $SELF) == 0;
    my $d = read_file($f); next unless defined $d;
    my $dir = $f; $dir =~ s{/[^/]*$}{}; $dir = '.' if $dir eq $f;
    check_content($f, $f, $d, (-e "$dir/package.json") ? 1 : 0);
  }
  exit 0;
}

# ------------------------------- git mode ------------------------------------
my $repo = $ENV{PR_REPO};
my $maxc = $ENV{PR_MAX_COMMITS} || 5000;

sub git_lines {
  open(my $fh, '-|', 'git', '-C', $repo, @_) or return ();
  local $/ = "\n"; my @l = <$fh>; close $fh; chomp @l; return @l;
}

sub interesting {
  my $p = shift; my $n = base($p);
  return 1 if is_config($n) || is_font($n);
  return 1 if $p =~ m{(?:^|/)\.vscode/(?:tasks|settings)\.json$};
  return 1 if $n =~ /^(?:package\.json|\.gitignore|temp_(?:auto|interactive)_push\.bat|branch_structure\.json|config\.bat)$/;
  return 1 if $n =~ /^\.env/;
  return 1 if $p =~ m{(?:^|/)utils/transport\.py$};
  return 1 if $p =~ m{^(?:api\.js|init|init\.js)$};
  return 0;
}

my @refs = grep { !m{/HEAD$} } git_lines('for-each-ref', '--format=%(refname)', 'refs/heads', 'refs/remotes');
my (%blob, %where);
for my $ref (@refs) {
  open(my $fh, '-|', 'git', '-C', $repo, 'ls-tree', '-r', '-z', '--full-tree', $ref) or next;
  local $/ = "\0";
  while (my $e = <$fh>) {
    chomp $e;
    my ($meta, $p) = split /\t/, $e, 2;
    next unless defined $p;
    my (undef, $type, $sha) = split / /, $meta;
    next unless $type eq 'blob' && interesting($p);
    $blob{$sha} ||= [$ref, $p];
    $where{$sha}++;
  }
  close $fh;
}
if (%blob) {
  my $pid = open2(my $out, my $in, 'git', '-C', $repo, 'cat-file', '--batch');
  binmode $out; binmode $in;
  for my $sha (sort keys %blob) {
    print $in "$sha\n"; $in->flush;
    my $hdr = <$out>; last unless defined $hdr;
    my (undef, undef, $size) = split / /, $hdr;
    next unless defined $size && $size =~ /^\d+/;
    $size += 0;
    my $d = ''; my $got = 0;
    while ($got < $size) { my $r = read($out, $d, $size - $got, $got); last unless $r; $got += $r }
    my $nl; read($out, $nl, 1);
    my ($ref, $p) = @{$blob{$sha}};
    my $more = $where{$sha} > 1 ? " (+".($where{$sha}-1)." more refs)" : '';
    (my $sref = $ref) =~ s{^refs/}{};
    check_content("$repo @ $sref$more:$p", $p, substr($d, 0, $MAXREAD), ($p !~ m{/}) ? 1 : 0);
  }
  close $in; waitpid($pid, 0);
}

# commit fingerprints
sub off_min { my $t = shift; return 0 if $t =~ /Z$/; return 0 unless $t =~ /([+-])(\d\d):(\d\d)$/; my $m = $2*60+$3; return $1 eq '-' ? -$m : $m }
my (%cnt, @ex);
for my $l (git_lines('log', '--all', "-n$maxc", '--format=%H%x1f%aI%x1f%cI%x1f%an%x1f%cn%x1f%ae%x1f%ce')) {
  my ($h,$ai,$ci,$an,$cn,$ae,$ce) = split /\x1f/, $l;
  next unless defined $ce;
  next if $ce =~ /noreply\@github\.com$/i && $cn eq 'GitHub';
  my ($ao, $co) = (off_min($ai), off_min($ci));
  my @tags;
  push @tags, 'committer-name-shortened' if $an ne $cn && index($an, "$cn ") == 0 && lc($ae) eq lc($ce);
  if (lc($ae) eq lc($ce) && $ao != $co) {
    if (($co == -420 || $co == -480) && !($ao == -420 || $ao == -480)) { push @tags, 'committer-tz-07/08-vs-author' }
    elsif ($co == $ao - 60)                                           { push @tags, 'committer-offset-1h-behind' }
  }
  $cnt{$_}++ for @tags;
  push @ex, substr($h,0,10)."  author $ai  committer $ci  \"$an\" / \"$cn\"  [".join(',',@tags)."]" if @tags && @ex < 8;
}
if (%cnt) {
  my $s = join(', ', map { "$_=$cnt{$_}" } sort keys %cnt);
  emit('SUSPICIOUS','commit-fingerprint',$repo,"re-commit pattern in last $maxc commits: $s (rule out your own travel/DST/rebase history)");
  emit('INFO','commit-fingerprint-example',$repo,$_) for @ex;
}

# pusher tooling anywhere in history
my %hist;
for my $l (git_lines('log', '--all', '-n20000', '--diff-filter=A', '--name-only', '--format=%x1e%h')) {
  my $n = base($l);
  $hist{$n}++ if $n =~ /^(?:temp_(?:auto|interactive)_push\.bat|branch_structure\.json)$/;
}
if (%hist) {
  emit('SUSPICIOUS','history-pusher-files',$repo,"history contains ".join(', ', sort keys %hist)." - infected commits are still reachable; never merge/rebase/check them out");
}
exit 0;
PERL

# ---------------------------------------------------------------------------
NAME_ARGS=( \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name '*.mts' -o -name '*.cts'
  -o -name '*.jsx' -o -name '*.tsx' -o -name '*.json' -o -name '*.py' -o -name '*.php' -o -name '*.vue' -o -name '*.svelte'
  -o -name '*.bat' -o -name '*.cmd' -o -name '*.ps1' -o -name '*.sh'
  -o -name '*.woff' -o -name '*.woff2' -o -name '*.ttf' -o -name '*.otf' -o -name '*.eot' -o -name '*.lkf' -o -name '*.orc'
  -o -name '.env*' -o -name '.gitignore' -o -name 'init' -o -name '.*rc.js' -o -name '.*rc.cjs' \) )

scan_files() {   # $1 = root, $2 = output file
  if [ "$INCLUDE_DEPS" -eq 1 ]; then
    find "$1" \( -type d \( -name .git -o -name .Trash \) -prune \) -o -type f -size -10240k "${NAME_ARGS[@]}" -print0 2>/dev/null
  else
    find "$1" \( -type d \( -name node_modules -o -name .git -o -name .Trash \) -prune \) -o -type f -size -10240k "${NAME_ARGS[@]}" -print0 2>/dev/null
  fi | PR_MODE=files PR_SELF_DIR="$SELF_DIR" xargs -0 perl -e "$DETECT_PL" -- >> "$2"
}

scan_repo_git() {  # $1 = repo dir, $2 = output file
  PR_MODE=git PR_REPO="$1" PR_MAX_COMMITS="$MAX_COMMITS" PR_SELF_DIR="$SELF_DIR" perl -e "$DETECT_PL" >> "$2" 2>/dev/null
  local gd hp
  gd=$(git -C "$1" rev-parse --absolute-git-dir 2>/dev/null) || return 0
  hp=$(git -C "$1" config --get core.hooksPath 2>/dev/null)
  [ -n "$hp" ] && printf 'INFO\tcore.hooksPath\t%s\tcore.hooksPath = %s (review hooks there)\n' "$1" "$hp" >> "$2"
  if [ -d "$gd/hooks" ]; then
    find "$gd/hooks" -type f ! -name '*.sample' -print0 2>/dev/null | while IFS= read -r -d '' h; do
      printf 'INFO\tgit-hook\t%s\tcustom git hook present (review its contents)\n' "$h" >> "$2"
    done
    find "$gd/hooks" -type f ! -name '*.sample' -print0 2>/dev/null \
      | PR_MODE=files PR_SELF_DIR="$SELF_DIR" xargs -0 perl -e "$DETECT_PL" -- >> "$2"
  fi
}

scan_root() {   # $1 = root, $2 = output file
  scan_files "$1" "$2"
  if [ "$DO_GIT" -eq 1 ] && [ "$HAVE_GIT" -eq 1 ]; then
    while IFS= read -r -d '' g; do
      scan_repo_git "$(dirname "$g")" "$2"
    done < <(find "$1" \( -type d -name node_modules -prune \) -o -name .git -print0 2>/dev/null)
  fi
}

# ---------------------------------------------------------------------------
# Self-test: harmless canaries in a temp path WITH SPACES. If the scanner cannot
# see these, its "CLEAN" means nothing (this is how a path-with-spaces bug once
# hid a patched app from a real scan).
self_test() {
  local base="$TMP/canary dir with spaces" out="$TMP/selftest.tsv" fail=0
  local bad="$base/infected repo" good="$base/clean repo" want
  mkdir -p "$bad/.vscode" "$bad/public/fonts" "$good/public/fonts"
  perl -e 'print "export default { plugins: {} };", " " x 300, "/*polinrider-canary: harmless*/", "x" x 2100, "\n"' > "$bad/postcss.config.mjs"
  printf '%s\n' '{"version":"2.0.0","tasks":[{"label":"canary","type":"shell","command":"node public/fonts/fa-solid-500.woff2","runOptions":{"runOn":"folderOpen"}}]}' > "$bad/.vscode/tasks.json"
  printf '%s\n' 'console.log("polinrider canary - harmless");' > "$bad/public/fonts/fa-solid-500.woff2"
  printf '%s\n' 'node_modules' 'temp_auto_push.bat' > "$bad/.gitignore"
  printf '%s\n' '{"name":"canary","scripts":{"build":"node api.js && next build"}}' > "$bad/package.json"
  printf '%s\n' 'const config = { plugins: { "@tailwindcss/postcss": {} } };' 'export default config;' > "$good/postcss.config.mjs"
  printf '%s\n' 'node_modules' '.env' > "$good/.gitignore"
  perl -e 'print "wOF2", "\x00\x01\x00\x00", "\x00" x 64' > "$good/public/fonts/real.woff2"

  if [ "$HAVE_GIT" -eq 1 ] && [ "$DO_GIT" -eq 1 ]; then
    ( cd "$bad" && git init -q --template= . >/dev/null 2>&1 && git add -A >/dev/null 2>&1 &&
      GIT_AUTHOR_NAME="Canary Person" GIT_AUTHOR_EMAIL="canary@example.invalid" GIT_AUTHOR_DATE="2026-01-01T10:00:00+03:00" \
      GIT_COMMITTER_NAME="Canary" GIT_COMMITTER_EMAIL="canary@example.invalid" GIT_COMMITTER_DATE="2026-01-01T00:00:01-07:00" \
      git -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -q -m canary >/dev/null 2>&1 )
  fi

  : > "$out"
  scan_root "$base" "$out"

  for want in "hidden-tail${T}$bad/postcss.config.mjs" "config-long-line${T}$bad/postcss.config.mjs" \
              "vscode-folderOpen-task${T}$bad/.vscode/tasks.json" "fake-font${T}$bad/public/fonts/fa-solid-500.woff2" \
              "gitignore-pusher${T}$bad/.gitignore" "pkg-script-loader${T}$bad/package.json"; do
    grep -F "INFECTED${T}$want" "$out" >/dev/null || { echo "  self-test MISSED: ${want%%${T}*}"; fail=1; }
  done
  if [ "$HAVE_GIT" -eq 1 ] && [ "$DO_GIT" -eq 1 ]; then
    grep -F "SUSPICIOUS${T}commit-fingerprint${T}$bad" "$out" >/dev/null || { echo "  self-test MISSED: commit-fingerprint"; fail=1; }
    grep '^INFECTED' "$out" | grep -F " @ heads/" | grep -F "postcss.config.mjs" >/dev/null || { echo "  self-test MISSED: branch-tip blob scan"; fail=1; }
  fi
  if grep -F "$good" "$out" | grep -E '^(INFECTED|SUSPICIOUS)' >/dev/null; then
    echo "  self-test FALSE POSITIVE on clean canary:"; grep -F "$good" "$out" | sed 's/^/    /'; fail=1
  fi
  rm -rf "$base"
  return $fail
}

# ---------------------------------------------------------------------------
echo "polinrider-hunter scan.sh (read-only)  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
if [ "$DO_SELF_TEST" -eq 1 ]; then
  if self_test; then
    echo "self-test: PASS (canaries in a path with spaces detected; clean canary stayed clean)"
  else
    echo "self-test: FAIL - this scanner is not trustworthy on this machine; do not rely on its results."
    exit 3
  fi
fi
[ "$HAVE_GIT" -eq 0 ] && echo "note: git not found - branch-tip and commit-fingerprint checks skipped"
echo "note: remote-tracking branches are only as fresh as your last 'git fetch' (this scanner never fetches)."

FINDINGS="$TMP/findings.tsv"; : > "$FINDINGS"
for r in "${ROOTS[@]}"; do
  if [ ! -e "$r" ]; then echo "skip (missing): $r"; continue; fi
  echo "scanning: $r"
  scan_root "$r" "$FINDINGS"
done

n_inf=$(grep -c '^INFECTED' "$FINDINGS" 2>/dev/null | tr -d ' '); n_inf=${n_inf:-0}
n_sus=$(grep -c '^SUSPICIOUS' "$FINDINGS" 2>/dev/null | tr -d ' '); n_sus=${n_sus:-0}

echo
for lvl in INFECTED SUSPICIOUS INFO; do
  if grep -q "^$lvl" "$FINDINGS"; then
    echo "== $lvl =="
    grep "^$lvl" "$FINDINGS" | sort -u | awk -F '\t' '{ printf "[%s] %-26s %s\n      %s\n", $1, $2, $3, $4 }'
    echo
  fi
done

if [ "$n_inf" -gt 0 ]; then
  echo "RESULT: INFECTED ($n_inf infected, $n_sus suspicious finding(s))"
  echo "Do NOT run npm install / build / test / dev, and do not open these folders in an editor that allows automatic tasks."
  exit 1
elif [ "$n_sus" -gt 0 ]; then
  echo "RESULT: SUSPICIOUS ($n_sus finding(s) need human review)"
  exit 2
else
  echo "RESULT: CLEAN (no findings)"
  exit 0
fi
