# Contributing

Start with a reproducible problem and a small synthetic input. New detections need a positive case, a legitimate negative case, boundary tests, and an explanation of false positives. Parser changes must preserve the distinction between an observed failure and an unknown outcome.

Use Python's standard library unless a concrete requirement justifies a dependency. Keep state and record sizes bounded. Expose data loss and unsupported input; do not silently convert malformed data into a clean result. Keep code comments and docstrings in Latin, and public commands and documentation in English.

Run `python3 -m unittest discover -s tests -v` before opening a pull request. Include the Python version, expected behavior, actual behavior, and synthetic reproduction. Never include production logs, private addresses, tokens, passwords, or account details.
