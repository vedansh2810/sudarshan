"""Generate SHA-256 checksum files for ML model integrity verification.

Usage:
    python -m app.ml.sign_model data/ml_models/fp_classifier_v1.joblib

This creates a .sha256 sidecar file that the classifier verifies
before loading the model, preventing arbitrary code execution
via poisoned joblib files.
"""

import sys
import hashlib
import os


def sign_model(path):
    """Generate SHA-256 checksum for a model file."""
    if not os.path.exists(path):
        print(f"Error: File not found: {path}")
        sys.exit(1)

    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    checksum = sha256.hexdigest()
    checksum_path = path + ".sha256"
    with open(checksum_path, "w") as f:
        f.write(checksum)

    print(f"Model:    {path}")
    print(f"SHA-256:  {checksum}")
    print(f"Written:  {checksum_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.ml.sign_model <model_path>")
        sys.exit(1)
    sign_model(sys.argv[1])
