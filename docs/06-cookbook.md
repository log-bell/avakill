# Cookbook

Practical recipes for common AvaKill workflows.

## Sandbox Recipes

### Set up sandbox from scratch

```bash
# 1. Run interactive setup — say "y" when asked about sandbox
avakill setup

# 2. Verify the sandbox is working
avakill sandbox verify --policy avakill.yaml

# 3. Launch an agent inside the sandbox
avakill launch --policy avakill.yaml -- aider
```

### Preview before launching

Inspect exactly what the sandbox will restrict before running anything:

```bash
avakill launch --dry-run --policy avakill.yaml -- aider
```

This prints the platform, backend, allowed write paths, denied read paths, network rules, and the full generated SBPL profile. No process is launched.

### Debug a sandbox denial

When an agent fails inside the sandbox:

```bash
# 1. Preview the profile to see what's allowed/blocked
avakill launch --dry-run --policy avakill.yaml -- echo test

# 2. Watch sandbox denial logs in real time (macOS)
log stream --predicate 'subsystem == "com.apple.sandbox"'

# 3. Find the blocked path in the log, then add it to your policy
#    Edit avakill.yaml → sandbox → allow_paths → write (or deny_paths → read)

# 4. Re-verify after the change
avakill sandbox verify --policy avakill.yaml
```

### Add a custom write path

If an agent needs to write to a directory not in the defaults (e.g. a build output directory):

```yaml
# avakill.yaml
sandbox:
  allow_paths:
    write:
      - /tmp
      - .                           # workspace
      - /Users/you/project/build    # add your custom path
```

Then verify the change:

```bash
avakill sandbox verify --policy avakill.yaml
```

### Test that sensitive paths are blocked

Use `ls`, `head`, or `stat` to test — **not** `cat` (which hangs when `open()` fails because it falls back to reading stdin):

```bash
# Launch a shell inside the sandbox
avakill launch --policy avakill.yaml -- /bin/sh

# Inside the sandbox shell:
ls ~/.ssh          # should fail (Permission denied)
stat ~/.aws        # should fail
head -1 ~/.gnupg   # should fail

# These should work:
ls /tmp            # allowed write path
ls /usr/bin        # broad reads are allowed
```
