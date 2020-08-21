## -*- docker-image-name: "libmatch" -*-
FROM angr/angr
MAINTAINER edg@cs.ucsb.edu
RUN apt-get update && apt-get install -y sudo automake virtualenvwrapper python3-pip python3-dev python-dev build-essential libxml2-dev \
                      libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap debian-archive-keyring \
                      libglib2.0-dev libpixman-1-dev screen binutils-multiarch nasm vim libssl-dev 
USER angr
RUN git clone https://github.com/subwire/autoblob /home/angr/angr-dev/autoblob
RUN bash -c "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon angr && cd /home/angr/angr-dev/autoblob && pip install -e ."
COPY --chown=angr . /home/angr/angr-dev/libmatch
RUN bash -c "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon angr && cd /home/angr/angr-dev/libmatch && pip install -e ."

WORKDIR /home/angr/angr-dev/libmatch


