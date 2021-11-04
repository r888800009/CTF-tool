# FROM ubuntu:18.04
ARG VERSION=18.04
FROM ubuntu:${VERSION} AS basic

RUN apt-get update -y \
&& apt-get install gcc gdb curl vim python3 make -y

ENV LANG en_US.UTF-8 

# install gef
RUN bash -c "$(curl -fsSL http://gef.blah.cat/sh)"

FROM basic AS ctf
# install pwntools
RUN apt-get update -y\
&& apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential -y\
&& python3 -m pip install --upgrade pip\
&& python3 -m pip install --upgrade pwntools

# install angr
RUN apt-get install python3-dev libffi-dev build-essential virtualenvwrapper -y\
&& pip install angr

# install z3
RUN pip install z3-solver

CMD ["bash"]
