# Gunicorn configuration file
import multiprocessing

bind = "0.0.0.0:5000"
workers = 1
# Give Gemini API plenty of time to process large PDFs
timeout = 600
# Restart workers after this many requests to prevent memory leaks
max_requests = 10
max_requests_jitter = 2
