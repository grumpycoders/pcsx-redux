#!/bin/bash

function clean() {
  f="$1"
  fromdos "$f"
  tabremover -t 8 "$f" "$f".2
  mv "$f.2" "$f"
}

function format() {
  f="$1"
  if [ "${f##*.}" != "lua" ]; then
    clang-format --style=file "$f" > "$f.2"
  else
    lua-format "$f" --config=/lua-format.config > "$f.2"
  fi
  mv "$f.2" "$f"
  sed "s/ *$//" -i "$f"
}

find repository/src -name *.c -or -name *.cc -or -name *.cpp -or -name *.h -or -name *.hh -or -name *.lua | while read f ; do
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
