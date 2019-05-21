#!/bin/bash

function clean() {
  f="$1"
  fromdos "$f"
  tabremover -t 8 "$f" "$f".2
  mv "$f.2" "$f"
}

function format() {
  f="$1"
  clang-format --style=file "$f" > "$f.2"
  mv "$f.2" "$f"
  sed "s/ *$//" -i "$f"
}

find repository/src -name *.c -or -name *.cc -or -name *.h | while read f ; do
  echo "$f"
  clean "$f"
  format "$f"
done

find repository/vsprojects -name *.vcxproj | while read f ; do
  echo "$f"
  clean "$f"
done

find repository/i18n -type f | while read f ; do
  echo "$f"
  clean "$f"
done
