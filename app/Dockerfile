FROM debian:latest

WORKDIR /app

RUN apt-get update && apt-get install -y python3 python3-pip nmap
COPY ./project.py /app
COPY ./requirements.txt /app

RUN pip3 install -r requirements.txt --break-system-packages

CMD [ "python3", "./project.py" ]
