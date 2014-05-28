#!/bin/sh

./cpor-tag-file test-file;
./cpor-gen-challenge test-file;
./cpor-calc-response test-file;
./cpor-verify-response test-file;
