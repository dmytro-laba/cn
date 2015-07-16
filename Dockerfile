FROM ubuntu:14.04

RUN locale-gen en_US en_US.UTF-8
ENV LANG en_US.UTF-8

RUN apt-get update && \
    apt-get install -y software-properties-common \
                       python3 python3-setuptools python3-dev python3-lxml libpq-dev  git  mercurial build-essential \
                       libjpeg8 libjpeg-dev  libfreetype6 libfreetype6-dev zlib1g-dev libxml2-dev libxslt1-dev \
                       libcairo2 libpango1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info libcurl4-openssl-dev && \
                       apt-get purge python3-pip && easy_install3 pip


RUN adduser --disabled-password --gecos '' --home /usr/src/www-app www-app && adduser www-app sudo && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY . /usr/src/www-app
WORKDIR /usr/src/www-app

RUN pip3 install -r requirements.txt

ENV DEBUG 0

RUN chown -R www-app /usr/src/www-app

VOLUME /secret
RUN chown -R www-app /secret
RUN chmod -R 777 /secret


USER www-app

ENV HOME /usr/src/www-app