FROM python:3.8-slim

RUN apt update && apt install python-pip -y && pip install requests boto3 

ADD script.py /

RUN apt-get autoclean

ENTRYPOINT [ "python", "./script.py" ]
