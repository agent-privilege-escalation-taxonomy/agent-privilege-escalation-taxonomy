#!/usr/bin/env bash
set -euo pipefail
jar="${TLA2TOOLS_JAR:-}"
if [ -z "$jar" ] && [ -f "tools/tla2tools.jar" ]; then
  jar="tools/tla2tools.jar"
fi
if [ -z "$jar" ] && [ -f "../_tools/tla2tools.jar" ]; then
  jar="../_tools/tla2tools.jar"
fi
java_cmd=java
if ! command -v java >/dev/null 2>&1; then
  if command -v java.exe >/dev/null 2>&1; then
    java_cmd=java.exe
  fi
fi
if command -v "$java_cmd" >/dev/null 2>&1 && [ -n "$jar" ] && [ -f "$jar" ]; then
  jar_path=$(realpath "$jar")
  if [ "$java_cmd" = "java.exe" ] && command -v wslpath >/dev/null 2>&1; then
    jar_path=$(wslpath -w "$jar_path")
  fi
  (cd specs && "$java_cmd" -XX:+UseParallelGC -cp "$jar_path" tlc2.TLC -workers auto -config DenyByDefault.cfg DenyByDefault.tla)
else
  echo "SKIP formal model: java or tla2tools.jar not found"
fi
