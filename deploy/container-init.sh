#!/bin/sh
set -eu
node /app/dist/cli.js init
chown -R 1000:1000 /data /secrets
