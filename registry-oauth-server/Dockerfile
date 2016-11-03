FROM ubuntu:14.04
RUN apt-get update && apt-get install -y python-pip python-dev
RUN mkdir -p /server
ADD requirements.txt /server/requirements.txt
WORKDIR /server
RUN pip install -r requirements.txt

RUN useradd -m -u 1001 auth

ADD . /server
EXPOSE 8080
CMD python app.py
