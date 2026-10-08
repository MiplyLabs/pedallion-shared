# Development gate commands. .claude/gate.json points at these targets.

# Homebrew rust ships without llvm-tools, so coverage uses brew's llvm@<N>, which must match the
# LLVM major that `rustc -vV` reports. Without brew, cargo-llvm-cov finds rustup's llvm-tools.
LLVM_PREFIX ?= $(shell brew --prefix --installed llvm@22 2>/dev/null)
ifneq ($(LLVM_PREFIX),)
export LLVM_COV ?= $(LLVM_PREFIX)/bin/llvm-cov
export LLVM_PROFDATA ?= $(LLVM_PREFIX)/bin/llvm-profdata
endif

COMPARE_BRANCH ?= origin/master
COVERAGE_MIN ?= 80

.PHONY: quick fast full security lint test secrets secrets-branch coverage audit sast

# G2: after every Claude turn that changed files.
quick: lint test

# G3: before every commit.
fast: lint test secrets

# G4: before push / PR.
full: fast coverage

security: audit sast secrets-branch

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

test:
	cargo test

secrets:
	gitleaks git --staged --redact --no-banner .

# Every commit on the branch. Before the first push there is no base, so scan everything.
secrets-branch:
	@if git rev-parse --verify --quiet "$(COMPARE_BRANCH)^{commit}" >/dev/null; then \
		gitleaks git --redact --no-banner --log-opts="$(COMPARE_BRANCH)..HEAD" . ; \
	else \
		gitleaks git --redact --no-banner . ; \
	fi

# Changed-line coverage needs a base branch; before the first push, require total coverage.
coverage:
	cargo llvm-cov --lcov --output-path target/lcov.info
	@if git rev-parse --verify --quiet "$(COMPARE_BRANCH)^{commit}" >/dev/null; then \
		diff-cover target/lcov.info --compare-branch=$(COMPARE_BRANCH) --fail-under=$(COVERAGE_MIN) ; \
	else \
		cargo llvm-cov report --fail-under-lines $(COVERAGE_MIN) ; \
	fi

audit:
	cargo audit

sast:
	semgrep scan --config p/rust --error --metrics=off --quiet src examples
