---
name: commit
description: Create a git commit with conventional commit message format
disable-model-invocation: true
allowed-tools:
  - Bash(git *)
  - Bash(pytest *)
argument-hint: "[optional message]"
---

# Git Commit Skill

Create a git commit following conventional commit format with automated checks.

## Instructions

### 1. Review Changes

First, show what will be committed:
```bash
git status
```

Check staged changes:
```bash
git diff --staged
```

If nothing is staged, ask user what to stage.

### 2. Run Tests

**IMPORTANT**: Always run tests before committing:
```bash
pytest tests/ -v
```

If tests fail, STOP and report the failures. Do not create a commit with failing tests.

### 3. Analyze Changes

Based on the diff output, determine:
- **Type**: feat, fix, docs, style, refactor, test, chore, build
- **Scope**: The area of code affected (e.g., auth, api, wallet, verifier, crypto, did)
- **Description**: Short summary (max 50 chars)

### 4. Create Commit Message

**Format**: `type(scope): description`

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style/formatting (no logic change)
- `refactor`: Code restructuring (no behavior change)
- `test`: Adding or updating tests
- `chore`: Maintenance tasks (dependencies, config)
- `build`: Build system or dependencies

**Scope examples:**
- `crypto` - Cryptography utilities
- `did` - DID document handling
- `api` - API endpoints
- `wallet` - Wallet functionality
- `verifier` - Verifier interface
- `admin` - Admin panel
- `db` - Database operations
- `auth` - Authentication

**Good commit messages:**
```
feat(crypto): add Ed25519 key generation utility
fix(api): handle missing claim_id in verification endpoint
docs(readme): add installation instructions
refactor(did): simplify DID document creation logic
test(crypto): add signature verification tests
chore(deps): upgrade cryptography to 41.0.7
```

**Bad commit messages:**
```
update stuff
fix bug
wip
changes
asdf
```

### 5. Execute Commit

If user provided a message via arguments (`/commit "message"`), use it after validating format.

Otherwise, create a commit message based on the changes and execute:

```bash
git commit -m "type(scope): description"
```

For larger changes that need explanation, use multi-line format:
```bash
git commit -m "$(cat <<'EOF'
type(scope): short description

Longer explanation of the change.
- What was changed
- Why it was changed
- Any breaking changes or important notes

Refs #issue-number (if applicable)
EOF
)"
```

### 6. Confirm Success

Show the commit that was created:
```bash
git log -1 --oneline
```

And show current status:
```bash
git status
```

## Arguments Handling

If `$ARGUMENTS` is provided:
1. Validate it follows conventional commit format
2. If valid, use it directly: `git commit -m "$ARGUMENTS"`
3. If invalid, show error and suggest correct format

Arguments: $ARGUMENTS

## Validation Rules

**Commit message MUST:**
- Start with a valid type (feat, fix, docs, etc.)
- Have scope in parentheses (optional but recommended)
- Have colon after type(scope)
- Have space after colon
- Be 50 characters or less for first line
- Use present tense ("add" not "added")
- Not end with a period

**Reject commits that:**
- Use vague messages ("update", "fix", "wip")
- Are too long (>72 chars)
- Don't follow the format
- Have failing tests

## Examples

### Example 1: New Feature
```
Changes: Added wallet.js with localStorage management
Type: feat
Scope: wallet
Message: feat(wallet): add localStorage credential management
```

### Example 2: Bug Fix
```
Changes: Fixed signature verification in verifier
Type: fix
Scope: verifier
Message: fix(verifier): correct JWS signature decoding
```

### Example 3: Documentation
```
Changes: Updated PLAN.md with verifier component
Type: docs
Scope: plan
Message: docs(plan): add verifier interface specification
```

### Example 4: Tests
```
Changes: Added tests for DID document generation
Type: test
Scope: did
Message: test(did): add DID document generation tests
```

## Notes

- If unsure about scope, check `routes/`, `utils/`, `templates/` directories
- Keep messages concise but descriptive
- Reference issue numbers when fixing specific bugs
- For breaking changes, add `!` after scope: `feat(api)!: change credential format`
