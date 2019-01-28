#!/bin/sh

python2 setup.py clean --all
rm -r MANIFEST .coverage dist/slapdcheck* build/* *.egg-info .tox docs/.build/*
rm slapdcheck/*.py? slapdcheck/*/*.py? tests/*.py? *.py?
find -name "*.py?" -delete
find -name __pycache__ | xargs -n1 -iname rm -r name
rm -r slapdtest-[0-9]*
