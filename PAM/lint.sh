#!/bin/bash
cppcheck  --project=PAM.cppcheck \
           --enable=all \
             -i build/ \
             -i cmake-build-debug/ \
             -i pam_authenticator.c \
             --suppress=missingIncludeSystem \
             --check-level=exhaustive \
           --inconclusive \
           --std=c11 \
           --xml --xml-version=2 \
           2> cppcheck.xml
cppcheck-htmlreport --file=cppcheck.xml --report-dir=cppcheck-html  --source-dir=.
