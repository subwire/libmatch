FROM ubuntu:20.04
WORKDIR /root
ENV LC_CTYPE C.UTF-8
ARG DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386

RUN apt update -y
RUN apt install python3 python3-pip git vim build-essential unzip -y
RUN ln -s /usr/bin/python3 /usr/bin/python
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install angr==9.0.4495
RUN python3 -m pip install protobuf==3.20.0
RUN python3 -m pip install six

RUN git clone https://github.com/subwire/libmatch.git
RUN python3 -m pip install ./libmatch/
RUN git clone https://github.com/subwire/autoblob/
RUN python3 -m pip install ./autoblob/

WORKDIR /root
