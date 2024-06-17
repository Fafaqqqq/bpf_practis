#!/bin/bash

echo $PWD/../lib/libbpf


if [ -z "$(ls -A ../lib/libbpf)" ]; then
  echo $PWD/../lib/libbpf
fi