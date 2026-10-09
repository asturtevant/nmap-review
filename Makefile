# nmap-review
#
#   make test      the whole suite, offline, no nmap needed
#   make sample    regenerate the committed sample reports from the fixture
#   make check     test + confirm the committed sample matches the current rules

PY := python3

.PHONY: help test sample check clean

help:
	@echo "make test    run the test suite (offline, no nmap required)"
	@echo "make sample  regenerate the committed sample reports (md + html)"
	@echo "make check   test, then verify the committed sample is current"

test:
	$(PY) -m unittest discover -s tests -t . -v

sample:
	./nmap-review report tests/fixtures/sample.xml -f md   -o docs/sample-report.md
	./nmap-review report tests/fixtures/sample.xml -f html -o docs/sample-report.html
	./nmap-review diff tests/fixtures/baseline.xml tests/fixtures/sample.xml \
		-f md   -o docs/sample-diff.md
	./nmap-review diff tests/fixtures/baseline.xml tests/fixtures/sample.xml \
		-f html -o docs/sample-diff.html

# The sample report is committed so a change in the rules shows up as a diff in
# the review wording, not just in a test name. If this target fails, the rules
# changed and the sample needs regenerating -- which is the point.
# The HTML sample is compared inside the test suite (tests/test_html.py); the
# markdown one is compared here because a diff is the readable way to see a
# wording change.
check: test
	@./nmap-review report tests/fixtures/sample.xml -f md > /tmp/nmap-review-sample.md
	@./nmap-review diff tests/fixtures/baseline.xml tests/fixtures/sample.xml -f md \
		> /tmp/nmap-review-sample-diff.md
	@diff -u docs/sample-report.md /tmp/nmap-review-sample.md \
		&& diff -u docs/sample-diff.md /tmp/nmap-review-sample-diff.md \
		&& echo "  sample reports are current" \
		|| { echo "  docs/ samples are stale -- run 'make sample'"; exit 1; }

clean:
	rm -rf __pycache__ */__pycache__ .pytest_cache
