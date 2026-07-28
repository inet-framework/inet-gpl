#
# Front end for the packetdrill suite. See README.md.
#
# The INET run (INET's PacketDrillApp) is the default target and runs from the
# scripts under tests/protocol/tcp/ -- nothing outside this repository is needed
# beyond a built INET. The Linux run (the real Linux kernel) is a separate target: it
# re-records the checked-in linux-results.csv and needs /dev/net/tun plus the
# packetdrill binary.
#
# Both INET_ROOT and INETGPL_ROOT must be set, by cd-ing into each root and
# sourcing its setenv (in that order) -- their setenv scripts derive the root
# from the current directory, so sourcing them by absolute path silently sets
# the wrong one.
#
# Variables:
#   FILTER=<regex>   restrict to scripts whose id (path below tests/protocol) matches
#   TOLERANCE=<us>   Linux-run timing tolerance in microseconds (scripts that set
#                    their own --tolerance_usecs keep theirs)
#   PRIVILEGED=1     run the Linux run as real root (sudo) -- see README
#   PYTHON=<python>  interpreter to run suite.py with
#   PROTOCOL=<name>  the protocol folder to use (default tcp)
#
# Examples:
#   make                        # run all scripts in INET
#   make test                   # the INET run, then the scoreboard
#   make inet FILTER=fastopen   # just the Fast Open scripts
#   make linux PRIVILEGED=1      # the Linux run as root: 5 more scripts can run
#   make report summary         # rebuild the report and print the headline
#

PYTHON ?= python3
SUITE := $(PYTHON) suite.py
# the protocol whose scripts run: its folder under tests/packetdrill holds its configuration
PROTOCOL ?= tcp
export PACKETDRILL_PROTOCOL := $(PROTOCOL)

FILTER ?=
TOLERANCE ?=
PRIVILEGED ?=
FILTER_ARG := $(if $(FILTER),--filter '$(FILTER)',)
TOL_ARG := $(if $(TOLERANCE),--tolerance-usecs '$(TOLERANCE)',)
PRIV_ARG := $(if $(PRIVILEGED),--privileged,)

# opp_makemake names the output directory after the toolchain (clang-debug,
# gcc-debug, ...); suite.py discovers it the same way.
EXE := $(firstword $(wildcard build/out/*-debug/packetdrill_inet_dbg))

REPORT := out/report.md

.PHONY: all inet linux report test run preprocess summary build ensure-exe \
        rebuild verify-scripts check-env clean distclean help

# These targets are stages of one pipeline, not independent work: `report`
# reads what `inet` writes. A -j in the environment (nix dev shells commonly
# export MAKEFLAGS=-j$NIX_BUILD_CORES) would otherwise run them concurrently
# and produce a scoreboard from the previous run's results. The build sub-make
# still parallelises.
.NOTPARALLEL:

all: inet ## (default) run the scripts in INET's PacketDrillApp

inet: ensure-exe ## run the scripts in INET and record out/inet_results/
	$(SUITE) inet $(FILTER_ARG)

linux: ## run the scripts on the real Linux kernel and RE-RECORD linux-results.csv
	@echo "The Linux run re-records the checked-in linux-results.csv; it needs /dev/net/tun,"
	@echo "the packetdrill binary and ethtool. Interrupt now if that is not what you want."
	$(SUITE) linux $(FILTER_ARG) $(TOL_ARG) $(PRIV_ARG)

report: ## join both runs into out/report.json and out/report.md
	$(SUITE) compare $(FILTER_ARG)

test: inet report ## the everyday loop: the INET run, then a fresh scoreboard

run: ensure-exe ## both runs from scratch: the Linux run, the INET run and the report
	$(SUITE) run $(FILTER_ARG) $(TOL_ARG) $(PRIV_ARG)

preprocess: ## dry-run the preprocessor and sysctl mapping, no simulation
	$(SUITE) preprocess $(FILTER_ARG)

summary: ## print the headline scoreboard from the last report
	@test -f $(REPORT) || { echo "$(REPORT) not found -- run 'make test' first."; exit 1; }
	@sed -n '/^## Headline/,/^## /p' $(REPORT) | sed '$$d'

verify-scripts: ## check the script hashes against linux-results.csv and the helper paths of the Linux run
	$(SUITE) verify-scripts $(FILTER_ARG)

build: ## build the runner executable for the INET run
	@test -n "$(INET_ROOT)" -a -n "$(INETGPL_ROOT)" || { \
	    echo "INET_ROOT/INETGPL_ROOT are not set. Run:"; \
	    echo "  cd \$$INET_ROOT && source setenv -q && cd \$$INETGPL_ROOT && source setenv -q"; \
	    exit 1; }
	mkdir -p build
	cd build && opp_makemake -f --deep -lINET_dbg -lINETGPL_dbg \
	    -L$(INET_ROOT)/src -L$(INETGPL_ROOT)/src -P . \
	    -I$(INET_ROOT)/src -I$(INETGPL_ROOT)/src -o packetdrill_inet
	$(MAKE) -C build MODE=debug

rebuild: distclean build ## rebuild the runner from scratch

# Build the runner only when it is missing, so the run targets work from a
# bare checkout without a separate manual build step.
ensure-exe:
	@test -n "$(EXE)" || $(MAKE) build

check-env: ## check roots, PyYAML and the runner without running anything
	@test -n "$(INET_ROOT)"    || { echo "INET_ROOT is not set";    exit 1; }
	@test -n "$(INETGPL_ROOT)" || { echo "INETGPL_ROOT is not set"; exit 1; }
	@echo "INET_ROOT    = $(INET_ROOT)"
	@echo "INETGPL_ROOT = $(INETGPL_ROOT)"
	@echo "python       = $$(command -v $(PYTHON) || echo '$(PYTHON)')"
	@$(PYTHON) -c "import yaml" 2>/dev/null || { \
	    echo "PyYAML       = NOT importable by $$(command -v $(PYTHON) || echo '$(PYTHON)')"; \
	    echo "               a dev shell's own python3 is not necessarily the one it is"; \
	    echo "               installed for -- pass a working one as PYTHON=<path>"; \
	    exit 1; }
	@echo "PyYAML       = ok"
	@if command -v ethtool >/dev/null; then echo "ethtool      = $$(command -v ethtool)"; \
	 else echo "ethtool      = MISSING -- the Linux run only; mtu_probe and the nagle tests"; \
	      echo "               call it to disable tun0 offloads and silently mis-run without it"; fi
	@if command -v packetdrill >/dev/null; then echo "packetdrill  = $$(command -v packetdrill)"; \
	 else echo "packetdrill  = not found (the Linux run only)"; fi
	@if [ -n "$(EXE)" ]; then echo "runner       = $(EXE)"; \
	 else echo "runner       = not built (run 'make build')"; fi

clean: ## remove run artifacts (results, preprocessed scripts, pcaps)
	rm -rf out

distclean: clean ## also remove the built runner and its generated makefile
	rm -rf build/out build/Makefile build/packetdrill_inet_dbg build/packetdrill_inet

help: ## list the available targets
	@echo "packetdrill suite -- targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Variables: FILTER=<regex>  TOLERANCE=<usecs>  PRIVILEGED=1  PYTHON=<interpreter>"
