#!/bin/sh
find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.inc" \) -exec clang-format -i {} +


