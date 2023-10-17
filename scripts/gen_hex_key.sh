#! /bin/zsh

hexdump -vn32 -e'10/4 "%08X" 1 "\n"' /dev/urandom | sed 's/[ \t]*$$//'

