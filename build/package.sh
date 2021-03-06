#!/usr/bin/env bash
set -eu

ARCHIVE_NAME=verify-event-recorder-service.zip

if [ -d tmp/ ];
then
    rm -r tmp/
fi

if [ -f ${ARCHIVE_NAME} ];
then
    rm -f ${ARCHIVE_NAME}
fi

if [ -z "$(which virtualenv)" ];
then
    pip install virtualenv
fi

virtualenv --python=python3 package-env
package-env/bin/pip3.6 install -r requirements/prod.txt

mkdir -p tmp/src/
cp -r package-env/lib/python3.6/site-packages/ tmp/
cp -r src/ tmp/src/

echo "Zipping verify-event-recorder-service"
cd tmp
zip -qr ${ARCHIVE_NAME} .
mv ${ARCHIVE_NAME} ../
cd ..
echo "Zipping complete"

echo "Cleaning up temporary files"
rm -r tmp/