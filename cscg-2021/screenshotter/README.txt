To run the server hosting the payloads:

gunicorn -w 1 -b "0.0.0.0:8000" --access-logfile access.log --error-logfile error.log app:app
