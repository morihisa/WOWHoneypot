FROM python:3.7-alpine

WORKDIR /app
ADD . /app
RUN mkdir /app/log

CMD ["python", "wowhoneypot.py"]
