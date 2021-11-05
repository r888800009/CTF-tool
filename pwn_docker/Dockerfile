# FROM ubuntu:18.04
ARG VERSION=18.04
FROM ubuntu:${VERSION} AS basic

RUN apt-get update -y \
&& apt-get install gcc gdb curl vim python3 make -y

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8
RUN apt-get -y install locales \
&& sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
&& locale-gen --no-purge en_US.UTF-8

RUN apt-get install tmux -y

# install gef
RUN bash -c "$(curl -fsSL http://gef.blah.cat/sh)"

FROM basic AS ctf
# install pwntools
RUN apt-get update -y\
&& apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential -y\
&& python3 -m pip install --upgrade pip\
&& python3 -m pip install --upgrade pwntools==4.5.1

# install angr
RUN apt-get install python3-dev libffi-dev build-essential virtualenvwrapper -y\
&& pip install angr

# install z3
RUN pip install z3-solver

CMD ["bash"]
