#!/usr/bin/env bash

if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
    brew update
    brew install python3
    ln -s `which pip3` /usr/local/bin/pip
fi

pip install --upgrade setuptools pip
