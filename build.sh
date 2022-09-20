#!/usr/bin/env bash

set -eu

eslint src/*.ts
tsc -p tsconfig.json
