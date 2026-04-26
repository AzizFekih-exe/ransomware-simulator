import os
import time

TARGET_DIR = "demo_files"
EXTENSION = ".simulated"
RANSOM_NOTE = "README_RESTORE_FILES.txt"


def simulate_file_encryption():
    print("[SIMULATION] Starting safe ransomware simulation...\n")

    for root, _, files in os.walk(TARGET_DIR):
        for f in files:
            old_path = os.path.join(root, f)

            # Skip already simulated files
            if old_path.endswith(EXTENSION):
                continue

            new_path = old_path + EXTENSION

            try:
                os.rename(old_path, new_path)
                print(f"[SIMULATION] Renamed: {old_path} -> {new_path}")

                # Small delay to simulate real attack speed
                time.sleep(0.2)

            except Exception as e:
                print(f"[ERROR] Could not rename {old_path}: {e}")


def create_ransom_note():
    note_path = os.path.join(TARGET_DIR, RANSOM_NOTE)

    content = """
    ⚠️ YOUR FILES HAVE BEEN SIMULATED ⚠️

    This is a SAFE ransomware simulation for academic purposes.

    No real encryption has occurred.
    Your files were only renamed.

    To restore files:
    - Remove the '.simulated' extension

    (This is part of a cybersecurity training project)
    """

    try:
        with open(note_path, "w") as f:
            f.write(content.strip())

        print(f"\n[SIMULATION] Ransom note created: {note_path}")

    except Exception as e:
        print(f"[ERROR] Could not create ransom note: {e}")


def main():
    if not os.path.exists(TARGET_DIR):
        print(f"[ERROR] Directory '{TARGET_DIR}' does not exist.")
        return

    simulate_file_encryption()
    create_ransom_note()

    print("\n[SIMULATION] Completed successfully.")


if __name__ == "__main__":
    main()