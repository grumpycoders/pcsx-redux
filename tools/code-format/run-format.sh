#!/bin/sh

cd repository/src

find . -name *.c -or -name *.cc -or -name *.h | while read f ; do
  echo "$f"
  fromdos "$f"
  tabremover -t 8 "$f" "$f".2
  mv "$f.2" "$f"
  clang-format --style=file "$f" > "$f.2"
  mv "$f.2" "$f"
  sed "s/ *$//" -i "$f"
done
