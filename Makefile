# nmap-review
#
#   make test      the whole suite, offline, no nmap needed
#   make sample     regenerate docs/sample-report.md from the committed fixture
#   make check     test + confirm the committed sample matches the current rules

PY := python3

.PHONY: help test sample check clean

help:
	@echo "make test    run the test suite (offline, no nmap required)"
	@echo "make sample  regenerate docs/sample-report.md from tests/fixtures/sample.xml"
	@echo "make check   test, then verify the committed sample is current"

test:
	$(PY) -m unittest discover -s tests -t . -v

sample:
	./nmap-review report tests/fixtures/sample.xml -f md -o docs/sample-report.md

# The sample report is committed so a change in the rules shows up as a diff in
# the review wording, not just in a test name. If this target fails, the rules
# changed and the sample needs regenerating -- which is the point.
check: test
	@./nmap-review report tests/fixtures/sample.xml -f md > /tmp/nmap-review-sample.md
	@diff -u docs/sample-report.md /tmp/nmap-review-sample.md \
		&& echo "  sample report is current" \
		|| { echo "  docs/sample-report.md is stale -- run 'make sample'"; exit 1; }

clean:
	rm -rf __pycache__ */__pycache__ .pytest_cache
