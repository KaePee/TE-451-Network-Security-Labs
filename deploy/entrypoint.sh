#!/bin/sh
set -e
python manage.py migrate --noinput
python manage.py sync_labs
exec "$@"
