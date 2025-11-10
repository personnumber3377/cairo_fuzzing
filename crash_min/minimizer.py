#!/usr/bin/env python3
import subprocess
import sys
import os
import tempfile

# ----------- CONFIG -----------
TIMEOUT = 2.0   # seconds before considering execution "not crashing"
# ------------------------------

def causes_crash(exe, data):
    """Run executable with data as input. Returns True if crash is detected."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp.flush()
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [exe, tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=TIMEOUT
        )
        crashed = result.returncode < 0 or result.returncode > 128  # signal or abnormal code
    except subprocess.TimeoutExpired:
        crashed = False

    os.unlink(tmp_path)
    return crashed


def minimize(data, exe):
    """Delta-debug minimizing loop."""
    print(f"[+] Starting size: {len(data)} bytes")

    changed = True
    while changed:
        changed = False

        # Try removing chunks (binary chop)
        size = len(data)
        step = max(1, size // 2)

        while step > 0:
            print(f"[*] Step = {step} bytes...")
            i = 0
            while i + step <= len(data):
                candidate = data[:i] + data[i+step:]
                if causes_crash(exe, candidate):
                    print(f"[+] Reduced to {len(candidate)} bytes (removed chunk @ {i}:{i+step})")
                    data = candidate
                    changed = True
                    break
                i += step

            if changed:
                break
            step //= 2

    # Fine-grained byte deletion pass
    print("[*] Byte-by-byte shrinking...")
    i = 0
    while i < len(data):
        candidate = data[:i] + data[i+1:]
        if causes_crash(exe, candidate):
            print(f"[+] Removed byte @ {i}, new size {len(candidate)}")
            data = candidate
        else:
            i += 1

    print(f"[+] Done. Final crash size: {len(data)} bytes")
    return data


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <executable> <inputfile> <outputfile>")
        sys.exit(1)

    exe = sys.argv[1]
    infile = sys.argv[2]
    outfile = sys.argv[3]

    with open(infile, "rb") as f:
        data = f.read()

    print(f"[+] Testing initial crash...")

    if not causes_crash(exe, data):
        print("[!] ERROR: The provided input does NOT crash the binary!")
        sys.exit(1)

    minimized = minimize(data, exe)

    with open(outfile, "wb") as out:
        out.write(minimized)

    print(f"[✅] Saved minimized crash -> {outfile}")


if __name__ == "__main__":
    main()