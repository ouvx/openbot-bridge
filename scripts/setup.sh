#!/bin/sh
set -eu
umask 077
exec node "$(dirname "$0")/setup.mjs"
