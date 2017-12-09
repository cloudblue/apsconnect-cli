#!/usr/bin/env bash

if [[ $BUILD == 'OSX' ]]; then
    pyinstaller --onefile apsconnectcli/apsconnect.py
    mv dist/apsconnect dist/apsconnect-mac
fi

if [[ $BUILD == 'LINUX' ]]; then
    bash <(curl -s https://codecov.io/bash)
    pyinstaller --onefile apsconnectcli/apsconnect.py
    sudo add-apt-repository ppa:ubuntu-wine/ppa -y
    sudo apt-get update -qq
    sudo apt-get install -qq wine
    wget https://www.python.org/ftp/python/3.4.4/python-3.4.4.msi --output-document=python.msi
    wine msiexec /i python.msi /qn TARGETDIR=C:\\Python
    wine c:\\Python\\python.exe c:\\Python\\scripts\\pip.exe install pip --upgrade
    wine c:\\Python\\python.exe c:\\Python\\scripts\\pip.exe install pyinstaller --upgrade
    wine c:\\Python\\python.exe c:\\Python\\scripts\\pip.exe install -r requirements.txt
    wine c:\\Python\\scripts\\pyinstaller.exe --onefile apsconnectcli/apsconnect.py
fi