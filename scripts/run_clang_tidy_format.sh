#!/usr/bin/env bash
set -eo pipefail

. "$(dirname $0)"/common.sh

ensure_cheriot_benchmarks_root

CLANG_TIDY=/cheriot-tools/bin/clang-tidy
CLANG_FORMAT=/cheriot-tools/bin/clang-format
if [ -n "$1" ] ; then
	CLANG_TIDY=$1/clang-tidy
	CLANG_FORMAT=$1/clang-format
fi
if [ ! -x ${CLANG_TIDY} ] ; then
	echo Usage: $0 path/to/cheriot/tools/bin
	echo clang-tidy not found at ${CLANG_TIDY}
	exit 1
fi
if [ ! -x ${CLANG_FORMAT} ] ; then
	echo Usage: $0 path/to/cheriot/tools/bin
	echo clang-format not found at ${CLANG_FORMAT}
	exit 1
fi

PARALLEL_JOBS=$(nproc || sysctl -n kern.smp.cpus 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null)
DIRECTORIES=$BENCHMARKS

HEADERS=$(find ${DIRECTORIES} -name '*.h' -or -name '*.hh')
SOURCES=$(find ${DIRECTORIES} -name '*.cc')

echo Headers: ${HEADERS}
echo Sources: ${SOURCES}

echo ${CLANG_FORMAT} -i ${HEADERS} ${SOURCES}
${CLANG_FORMAT} -i ${HEADERS} ${SOURCES}
if ! git diff --exit-code ${HEADERS} ${SOURCES} ; then
	echo clang-format applied changes
	exit 1
fi

rm -f tidy.fail-*
# sh syntax is -c "string" [name [args ...]], so "tidy" here is the name and not included in "$@"
echo ${HEADERS} ${SOURCES} | xargs -P${PARALLEL_JOBS} -n1 sh -c "${CLANG_TIDY} --extra-arg=-DCLANG_TIDY -export-fixes=\$(mktemp -p. tidy.fail-XXXX) \$@" tidy
if [ $(find . -maxdepth 1 -name 'tidy.fail-*' -size +0 | wc -l) -gt 0 ] ; then
	# clang-tidy put non-empty output in one of the tidy-*.fail files
	cat tidy.fail-*
	exit 1
fi
