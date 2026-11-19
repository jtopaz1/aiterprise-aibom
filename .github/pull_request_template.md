## What and why

<!-- One change per pull request. What changes for someone who runs the scanner? -->

## What you ran

<!-- The commands and what they printed; say what you did not run. -->

- [ ] Tests that prove the change, and that fail without it: `PYTHONPATH=src python -m unittest discover -s tests -p "test_*.py"`
- [ ] The killer demo still finds all five: `python tools/killer_demo.py`
- [ ] The self-scan passes: `PYTHONPATH=src python -m aiterprise_scan scan . --offline --exclude "tests/**" --fail-on high --format table`
- [ ] A new or changed rule: `python tools/gen_rules_doc.py` run, and a benign near miss tested (CONTRIBUTING.md)
- [ ] `docs/STATUS.md` updated if something was built, changed or found not to work
- [ ] Every commit has a `Signed-off-by:` line (`git commit -s`, the DCO)
