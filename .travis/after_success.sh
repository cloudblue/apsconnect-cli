#!/usr/bin/env bash

bash <(curl -s https://codecov.io/bash)

if [[ $BUILD == 'OSX' ]]; then
    pyinstaller --add-data "VERSION:." --onefile apsconnectcli/apsconnect.py
    mv dist/apsconnect dist/apsconnect-mac
fi

if [[ $BUILD == 'LINUX' ]]; then
    pyinstaller --add-data "VERSION:." --onefile apsconnectcli/apsconnect.py
    mv dist/apsconnect dist/apsconnect-lin
    sudo add-apt-repository ppa:ubuntu-wine/ppa -y
    sudo apt-get update -qq
    sudo apt-get install -qq wine
    wget https://www.python.org/ftp/python/2.7.14/python-2.7.14.msi --output-document=python.msi
    wine msiexec /i python.msi /qn TARGETDIR=C:\\Python
    wine c:\\Python\\python.exe c:\\Python\\scripts\\pip.exe install pip --upgrade
    wine c:\\Python\\python.exe c:\\Python\\scripts\\pip.exe install pyinstaller --upgrade
    wine c:\\Python\\python.exe c:\\Python\\scripts\\pip.exe install -r requirements.txt
    wine c:\\Python\\scripts\\pyinstaller.exe --add-data "VERSION;." --onefile apsconnectcli/apsconnect.py
fi