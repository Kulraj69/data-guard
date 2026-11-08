"""Reproduces the demo video's real output: PII scan + reversible redaction."""
from data_guard import scan, Redactor

TEXT = ("Hi, I'm Ananya Verma, reach me at ananya.verma@gmail.com or +91 98110 22334. "
        "My card 4111 1111 1111 1111 expires 09/27, and my Aadhaar is 2345 6789 0123. "
        "Ship to 44 Rose Avenue, Patiala 147001.")
if __name__ == "__main__":
    red = Redactor()
    redacted, mapping = red.redact(TEXT)
    for f in mapping:
        print(f"found {f.kind}: '{TEXT[f.start:f.end]}' -> {f.placeholder}")
    print("redacted:", redacted)
    print("restore(redacted) == original:", red.restore(redacted) == TEXT)
