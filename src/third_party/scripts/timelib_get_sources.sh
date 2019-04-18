#!/bin/bash

set -o verbose
set -o errexit

# This script downloads and imports timelib
# timelib does not use any autotools/cmake/config system to it is a simple import.

# This script is designed to run on Linux or Mac OS X
# Parsers make use of re2c, which needs to be installed and be version 0.15.3
# *only*. re2c 0.16 introduces an issues with clang which causes any date
# parser to hang.
#

VERSION=2018.01alpha1
NAME=timelib
TARBALL=$VERSION.tar.gz
TARBALL_DIR=$NAME-$VERSION
TEMP_DIR=/tmp/temp-$NAME-$VERSION
DEST_DIR=`git rev-parse --show-toplevel`/src/third_party/$NAME-$VERSION

# Check prerequisites: re2c, wget
if ! [ -x "$(command -v re2c)" ]; then
    echo 'Error: re2c is not installed.' >&2
    exit 1
fi

RE2C_VERSION=`re2c --version`
if ! [ "re2c 0.15.3" == "$RE2C_VERSION" ]; then
    echo 'Error: re2c MUST be version 0.15.3.' >&2
    exit 1
fi

if ! [ -x "$(command -v wget)" ]; then
    echo 'Error: wget is not installed.' >&2
    exit 1
fi

if [ ! -f $TARBALL ]; then
    echo "Get tarball"
    wget https://github.com/derickr/timelib/archive/$TARBALL
fi

echo $TARBALL
tar -zxvf $TARBALL

rm -rf $TEMP_DIR
mv $TARBALL_DIR $TEMP_DIR
mkdir $DEST_DIR || true

cp -r $TEMP_DIR/* $DEST_DIR

cd $DEST_DIR

patch -p1 <<'EOF'
From 157caf3f66da49f4df55c532a7d82a5d0aa4be11 Mon Sep 17 00:00:00 2001
From: Derick Rethans <github@derickrethans.nl>
Date: Fri, 11 May 2018 10:51:02 +0100
Subject: [PATCH] Fixed #37: Incorrect snprintf invocation with static buffer

---
 Makefile         |  4 ++--
 parse_zoneinfo.c | 12 ++++++++++--
 2 files changed, 12 insertions(+), 4 deletions(-)

diff --git a/Makefile b/Makefile
index 2094595..b6acd1a 100644
--- a/Makefile
+++ b/Makefile
@@ -8,11 +8,11 @@ CFLAGS=-Wdeclaration-after-statement ${FLAGS}
 
 CPPFLAGS=${FLAGS}
 
-LDFLAGS=-lm -fsanitize=undefined
+LDFLAGS=-lm -fsanitize=undefined -l:libubsan.so.1
 
 TEST_LDFLAGS=-lCppUTest
 
-CC=gcc
+CC=gcc-8
 MANUAL_TESTS=tests/tester-parse-interval \
 	tests/tester-parse-tz tests/tester-iso-week tests/test-abbr-to-id \
 	tests/enumerate-timezones tests/date_from_isodate
diff --git a/parse_zoneinfo.c b/parse_zoneinfo.c
index 654348c..875d756 100644
--- a/parse_zoneinfo.c
+++ b/parse_zoneinfo.c
@@ -101,7 +101,8 @@ static int is_valid_tzfile(const struct stat *st, int fd)
  * length of the mapped data is placed in *length. */
 static char *read_tzfile(const char *directory, const char *timezone, size_t *length)
 {
-	char fname[MAXPATHLEN];
+	char *fname;
+	size_t fname_len;
 	char *buffer;
 	struct stat st;
 	int fd;
@@ -115,9 +116,16 @@ static char *read_tzfile(const char *directory, const char *timezone, size_t *le
 		return NULL;
 	}
 
-	snprintf(fname, sizeof(fname), "%s%s%s", directory, TIMELIB_DIR_SEPARATOR, timezone /* canonical_tzname(timezone) */);
+	fname_len = strlen(directory) + strlen(TIMELIB_DIR_SEPARATOR) + strlen(timezone) + 1;
+	fname = malloc(fname_len);
+	if (snprintf(fname, fname_len, "%s%s%s", directory, TIMELIB_DIR_SEPARATOR, timezone) < 0) {
+		free(fname);
+		return NULL;
+	}
 
 	fd = open(fname, O_RDONLY);
+	free(fname);
+
 	if (fd == -1) {
 		return NULL;
 	} else if (fstat(fd, &st) != 0 || !is_valid_tzfile(&st, fd)) {
-- 
2.17.1
EOF


# Prune files
rm -rf $DEST_DIR/tests
rm $DEST_DIT/zones/old-tzcode-32-bit-output.tar.gz || true

# Create parsers
echo "Creating parsers"
make parse_date.c parse_iso_intervals.c

# Create SConscript file
cat << EOF > SConscript
# This is a generated file, please do not modify. It is generated by
# timelib_get_sources.sh

Import('env')

env = env.Clone()

try:
    env.AppendUnique(CCFLAGS=[
        '-DHAVE_GETTIMEOFDAY',
        '-DHAVE_STRING_H',
    ])
    if env.TargetOSIs('windows'):
        env.AppendUnique(CCFLAGS=[
            '-DHAVE_IO_H',
            '-DHAVE_WINSOCK2_H',
        ])

        # C4996: '...': was declared deprecated
        env.Append(CCFLAGS=['/wd4996'])
    elif env.TargetOSIs('solaris'):
        env.AppendUnique(CCFLAGS=[
            '-DHAVE_DIRENT_H',
            '-DHAVE_STRINGS_H',
            '-DHAVE_UNISTD_H',
            '-D_POSIX_C_SOURCE=200112L',
        ])
    elif env.TargetOSIs('darwin'):
        env.AppendUnique(CCFLAGS=[
            '-DHAVE_DIRENT_H',
            '-DHAVE_SYS_TIME_H',
            '-DHAVE_UNISTD_H',
        ])
    else:
        env.AppendUnique(CCFLAGS=[
            '-DHAVE_DIRENT_H',
            '-DHAVE_SYS_TIME_H',
            '-DHAVE_UNISTD_H',
            '-D_GNU_SOURCE',
        ])
except ValueError:
    pass

env.Library(
    target='timelib',
    source=[
        'astro.c',
        'dow.c',
        'interval.c',
        'parse_date.c',
        'parse_iso_intervals.c',
        'parse_tz.c',
        'parse_zoneinfo.c',
        'timelib.c',
        'tm2unixtime.c',
        'unixtime2tm.c',
    ],
    LIBDEPS_TAGS=[
        'init-no-global-side-effects',
    ],
)
EOF

echo "Done"
