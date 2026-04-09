# Ransomware Simulator

## ⚠️ Safety Declaration

This project is developed strictly for educational purposes as part of IT360 at Tunis Business School.
All code in this repository simulates ransomware behavior in a controlled environment only.

- This code must NEVER be deployed outside of a locked Virtual Machine (VM)
- This code must NEVER be used on real files or real systems
- All testing is to be conducted on dummy data inside an isolated VM environment
- Unauthorized use of this code outside its academic context is strictly prohibited

## Team Roles

| Member | Role | Responsibilities |
|--------|------|-----------------|
| Rooya Jelassi | P1 — Project Manager | Overall coordination, timeline, risk management |
| Oussama Zmitri | P2 — Security Researcher | Threat modeling, kill chain documentation |
| Mohamed Aziz Fekih | P3 — Systems Architect | Repo setup, CI/CD pipeline, branch management |
| Ghayth Hajji | P4 — Developer | Core encryption module, dropper implementation |
| Noutayla Nefzaoui | P5 — VM & Testing Lead | VM environment setup, test execution |

## Branch Convention

All branches must follow this naming format:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `feat/` | New feature or implementation | `feat/encryption-module` |
| `docs/` | Documentation updates | `docs/kill-chain-analysis` |
| `fix/` | Bug fixes | `fix/key-generation-error` |

**Rules:**
- Never commit directly to `main`
- Always branch off the latest `main`
- Keep branch names lowercase and use hyphens, no spaces

## Commit Message Format

All commits must follow this format:

| Type | When to use |
|------|------------|
| `feat` | Adding new functionality |
| `fix` | Fixing a bug |
| `docs` | Documentation only changes |
| `chore` | Setup, config, or maintenance tasks |
| `test` | Adding or updating tests |

**Examples:**
- `feat(encryptor): add AES key generation`
- `docs(phase1): add kill chain analysis`
- `fix(dropper): handle missing file path`
- `chore(repo): initialize repo structure`