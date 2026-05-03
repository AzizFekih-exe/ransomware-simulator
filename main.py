"""
main.py — Unified Entry Point for the IT360 Ransomware Simulator
IT360 Project 14: Ransomware Simulator (Academic Use Only)

SAFETY:
    - Kill-switch is checked before any operation
    - All file operations scoped to test_files/ only
    - Requires DO_NOT_RUN.flag to be absent before running
    - Designed exclusively for air-gapped VM execution

"""

import os
import sys
import subprocess
import platform

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.common.config import (
    KILL_SWITCH_FILENAME,
    TARGET_DIRECTORY,
)


# ─────────────────────────────────────────────────────────────────────────────
#  DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def clear():
    """Clear the terminal screen cross-platform."""
    os.system("cls" if platform.system() == "Windows" else "clear")


def banner():
    """Print the simulator banner."""
    print("""
\033[31m
██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗
██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║
██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║
██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║
██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝
\033[0m
\033[32m  SIMULATOR\033[0m \033[90m— IT360 Project 14 | Academic Use Only\033[0m
\033[90m  ══════════════════════════════════════════════════\033[0m
\033[33m  [!] Run ONLY inside the air-gapped WindowsVictim VM\033[0m
\033[90m  ══════════════════════════════════════════════════\033[0m
""")


def print_status(label: str, value: str, color: str = "\033[32m"):
    """Print a formatted status line."""
    reset = "\033[0m"
    gray  = "\033[90m"
    print(f"  {gray}[{reset}{color}{label}{reset}{gray}]{reset}  {value}")


def section(title: str):
    """Print a section divider."""
    print(f"\n\033[34m  ── {title} {'─' * (44 - len(title))}\033[0m")


# ─────────────────────────────────────────────────────────────────────────────
#  KILL-SWITCH CHECK
# ─────────────────────────────────────────────────────────────────────────────

def check_kill_switch() -> None:
    """
    Halt the entire application if the kill-switch flag is present.
    This runs before ANY menu option is executed.
    """
    if os.path.exists(KILL_SWITCH_FILENAME):
        print(f"\n\033[31m  [KILL SWITCH]\033[0m '{KILL_SWITCH_FILENAME}' detected.")
        print("\033[31m  [KILL SWITCH]\033[0m Application halted. No files modified.")
        print(f"\n\033[90m  Remove '{KILL_SWITCH_FILENAME}' to enable execution.\033[0m\n")
        sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
#  SETUP — CREATE TEST FILES
# ─────────────────────────────────────────────────────────────────────────────

def setup_test_environment() -> None:
    """
    Create the test_files/ directory with sample files for demonstration.
    Safe to run multiple times — skips files that already exist.
    """
    section("Setting Up Test Environment")

    subdirs = [
        TARGET_DIRECTORY,
        os.path.join(TARGET_DIRECTORY, "documents"),
        os.path.join(TARGET_DIRECTORY, "reports"),
    ]

    for d in subdirs:
        os.makedirs(d, exist_ok=True)
        print_status("DIR ", f"Created {d}")

    test_files = {
        os.path.join(TARGET_DIRECTORY, "readme.txt")                : "This is a top-level readme file.",
        os.path.join(TARGET_DIRECTORY, "documents", "contract.txt") : "Confidential contract details.",
        os.path.join(TARGET_DIRECTORY, "documents", "notes.txt")    : "Personal notes — do not share.",
        os.path.join(TARGET_DIRECTORY, "reports",   "q3_report.txt"): "Q3 financial report data.",
        os.path.join(TARGET_DIRECTORY, "safe.exe")                  : "This file must never be encrypted.",
    }

    for filepath, content in test_files.items():
        if not os.path.exists(filepath):
            with open(filepath, "w") as f:
                f.write(content)
            print_status("FILE", f"Created {filepath}")
        else:
            print_status("SKIP", f"Already exists: {filepath}", "\033[90m")

    print("\n\033[32m  [✓] Test environment ready.\033[0m")


# ─────────────────────────────────────────────────────────────────────────────
#  OPTION 1 — RUN FULL KILL CHAIN
# ─────────────────────────────────────────────────────────────────────────────

def run_kill_chain() -> None:
    """
    Execute the full ransomware simulation kill chain via dropper.py.
    Stores the AES key output for use by the decryptor.
    """
    section("Full Kill Chain — Dropper Execution")
    check_kill_switch()

    # Check test files exist
    if not os.path.isdir(TARGET_DIRECTORY):
        print("\033[33m  [!] test_files/ not found. Run option [1] Setup first.\033[0m")
        return

    # Check there are encryptable files
    encryptable = []
    for root, _, files in os.walk(TARGET_DIRECTORY):
        for f in files:
            if any(f.endswith(ext) for ext in [".txt", ".pdf", ".docx", ".jpg", ".png", ".xlsx"]):
                encryptable.append(f)

    if not encryptable:
        print("\033[33m  [!] No encryptable files found. Run option [1] Setup first.\033[0m")
        return

    print(f"\n\033[90m  Files to encrypt: {len(encryptable)}\033[0m")
    print("\033[33m  [!] This will encrypt all target files in test_files/\033[0m")
    confirm = input("\n  Proceed? (yes/no): ").strip().lower()

    if confirm != "yes":
        print("\033[90m  Aborted.\033[0m")
        return

    print()
    from src.dropper.dropper import run_kill_chain as _run
    _run()


# ─────────────────────────────────────────────────────────────────────────────
#  OPTION 2 — RUN DECRYPTOR
# ─────────────────────────────────────────────────────────────────────────────

def run_decryptor() -> None:
    """
    Run the decryptor with the AES key from the previous kill chain run.
    """
    section("Decryptor — File Restoration")

    # Check there are locked files
    locked = []
    if os.path.isdir(TARGET_DIRECTORY):
        for root, _, files in os.walk(TARGET_DIRECTORY):
            for f in files:
                if f.endswith(".locked"):
                    locked.append(f)

    if not locked:
        print("\033[33m  [!] No .locked files found. Run the kill chain first.\033[0m")
        return

    print(f"\n\033[90m  Found {len(locked)} encrypted file(s).\033[0m")
    print("\n  Paste the AES key hex from the kill chain output:")
    aes_key_hex = input("  AES Key > ").strip()

    if len(aes_key_hex) != 64:
        print(f"\033[31m  [ERROR] AES key must be 64 hex characters (got {len(aes_key_hex)}).\033[0m")
        return

    print()
    from src.encryptor.decryptor import run_decryption
    run_decryption(TARGET_DIRECTORY, aes_key_hex)


# ─────────────────────────────────────────────────────────────────────────────
#  OPTION 3 — TEST KILL-SWITCH
# ─────────────────────────────────────────────────────────────────────────────

def test_kill_switch() -> None:
    """
    Create the kill-switch flag and verify the dropper halts immediately.
    Automatically removes the flag after the test.
    """
    section("Kill-Switch Test")

    print(f"  Creating '{KILL_SWITCH_FILENAME}'...")
    with open(KILL_SWITCH_FILENAME, "w") as f:
        f.write("kill-switch active")

    print("  Running dropper — must halt with no file modifications...\n")

    result = subprocess.run(
        [sys.executable, "src/dropper/dropper.py"],
        capture_output=True,
        text=True,
    )

    output = result.stdout + result.stderr
    print(output)

    if "KILL SWITCH" in output:
        print("\033[32m  [✓] Kill-switch test PASSED — dropper halted correctly.\033[0m")
    else:
        print("\033[31m  [✗] Kill-switch test FAILED — dropper did not halt.\033[0m")

    # Clean up the flag
    os.remove(KILL_SWITCH_FILENAME)
    print(f"\033[90m  '{KILL_SWITCH_FILENAME}' removed.\033[0m")


# ─────────────────────────────────────────────────────────────────────────────
#  OPTION 4 — RUN UNIT TESTS
# ─────────────────────────────────────────────────────────────────────────────

def run_unit_tests() -> None:
    """Run the full unit test suite and display results."""
    section("Unit Test Suite")

    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover",
         "-s", "tests/unit", "-v"],
        capture_output=True,
        text=True,
    )

    # unittest writes results to stderr
    output = result.stderr + result.stdout
    print(output)

    if result.returncode == 0:
        print("\033[32m  [✓] All tests passed.\033[0m")
    else:
        print("\033[31m  [✗] Some tests failed. See output above.\033[0m")


# ─────────────────────────────────────────────────────────────────────────────
#  OPTION 5 — SHOW STATUS
# ─────────────────────────────────────────────────────────────────────────────

def show_status() -> None:
    """Show current state of the test environment."""
    section("Environment Status")

    # Kill-switch
    ks = os.path.exists(KILL_SWITCH_FILENAME)
    print_status(
        "KILL-SWITCH",
        f"{'ACTIVE — execution blocked' if ks else 'inactive — execution allowed'}",
        "\033[31m" if ks else "\033[32m"
    )

    # test_files/
    if os.path.isdir(TARGET_DIRECTORY):
        all_files   = []
        locked      = []
        plain       = []
        notes       = []

        for root, _, files in os.walk(TARGET_DIRECTORY):
            for f in files:
                full = os.path.join(root, f)
                all_files.append(full)
                if f.endswith(".locked"):
                    locked.append(full)
                elif f == "README_RESTORE.txt":
                    notes.append(full)
                else:
                    plain.append(full)

        print_status("TOTAL FILES",   str(len(all_files)))
        print_status("PLAINTEXT",     f"{len(plain)}  file(s) — not yet encrypted",
                     "\033[32m")
        print_status("ENCRYPTED",     f"{len(locked)} file(s) — .locked",
                     "\033[31m" if locked else "\033[90m")
        print_status("RANSOM NOTES",  f"{len(notes)}  README_RESTORE.txt file(s)",
                     "\033[31m" if notes else "\033[90m")
        print_status("MANIFEST",      "present" if os.path.exists(".manifest.enc")
                     else "not found")
    else:
        print_status("test_files/", "NOT FOUND — run Setup first", "\033[33m")

    # Python info
    print_status("PYTHON", sys.version.split()[0])
    print_status("OS",     f"{platform.system()} {platform.release()}")


# ─────────────────────────────────────────────────────────────────────────────
#  OPTION 6 — RESET
# ─────────────────────────────────────────────────────────────────────────────

def reset_environment() -> None:
    """
    Delete all .locked files, ransom notes, and the manifest so the
    kill chain can be re-run from scratch without restoring the VM snapshot.
    For use during development only — in the real demo use the VM snapshot.
    """
    section("Reset Test Environment")

    print("\033[33m  [!] This removes all .locked files, ransom notes, and the manifest.\033[0m")
    confirm = input("  Proceed? (yes/no): ").strip().lower()

    if confirm != "yes":
        print("\033[90m  Aborted.\033[0m")
        return

    removed = 0

    # Remove .locked files and ransom notes from test_files/
    if os.path.isdir(TARGET_DIRECTORY):
        for root, _, files in os.walk(TARGET_DIRECTORY):
            for f in files:
                if f.endswith(".locked") or f == "README_RESTORE.txt":
                    path = os.path.join(root, f)
                    os.remove(path)
                    print_status("REMOVED", path, "\033[31m")
                    removed += 1

    # Remove manifest
    if os.path.exists(".manifest.enc"):
        os.remove(".manifest.enc")
        print_status("REMOVED", ".manifest.enc", "\033[31m")
        removed += 1

    # Recreate plaintext test files
    setup_test_environment()

    print(f"\n\033[32m  [✓] Reset complete. Removed {removed} artifact(s).\033[0m")
    print("\033[90m  Note: In the real demo always restore the VM snapshot instead.\033[0m")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────────────────────────────────────────

def menu() -> None:
    """Display the main menu and handle user selection."""

    options = {
        "1": ("Setup test environment",          setup_test_environment),
        "2": ("Run full kill chain",              run_kill_chain),
        "3": ("Run decryptor (restore files)",    run_decryptor),
        "4": ("Test kill-switch",                 test_kill_switch),
        "5": ("Run unit tests",                   run_unit_tests),
        "6": ("Show environment status",          show_status),
        "7": ("Reset environment",                reset_environment),
        "0": ("Exit",                             None),
    }

    while True:
        clear()
        banner()

        # Quick status line
        ks_active = os.path.exists(KILL_SWITCH_FILENAME)
        if ks_active:
            print(f"\033[31m  [KILL SWITCH ACTIVE] Remove '{KILL_SWITCH_FILENAME}' to enable execution.\033[0m\n")

        print("  \033[34mSelect an option:\033[0m\n")
        for key, (label, _) in options.items():
            color = "\033[31m" if key == "0" else "\033[32m"
            print(f"    {color}[{key}]\033[0m  {label}")

        print()
        choice = input("  \033[90m$\033[0m \033[32m>\033[0m ").strip()

        if choice not in options:
            print("\n\033[31m  [!] Invalid option.\033[0m")
            input("\n  Press Enter to continue...")
            continue

        if choice == "0":
            print("\n\033[90m  Exiting. Stay ethical.\033[0m\n")
            sys.exit(0)

        label, func = options[choice]
        print(f"\n\033[90m  ── {label}\033[0m")

        try:
            func()
        except KeyboardInterrupt:
            print("\n\033[33m  [!] Interrupted.\033[0m")
        except Exception as e:
            print(f"\n\033[31m  [ERROR] {e}\033[0m")

        input("\n  \033[90mPress Enter to return to menu...\033[0m")


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n\033[90m  Exited.\033[0m\n")
        sys.exit(0)