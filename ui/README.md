# Analyst console

The console is a zero-build static interface over the committed experiment result. From the repository
root, run `python -m http.server 8000` and open `http://localhost:8000/ui/`. It intentionally avoids a
separate frontend dependency tree in v0.1. The displayed claim boundaries match the implemented lab;
hardware boot and TUF/Uptane conformance are not presented as complete.

