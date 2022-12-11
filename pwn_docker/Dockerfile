# FROM ubuntu:18.04
ARG VERSION=18.04
FROM ubuntu:${VERSION} AS basic

RUN apt-get update -y \
&& apt-get install gcc gdb curl vim python3 cmake make sudo gawk bison patchelf -y

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN apt-get -y install locales \
&& sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
&& locale-gen --no-purge en_US.UTF-8

RUN apt-get install tmux git build-essential -y

# install gdb-peda-pwndbg-gef
RUN git clone https://github.com/apogiatzis/gdb-peda-pwndbg-gef && cd gdb-peda-pwndbg-gef && ./install.sh && cd /

FROM basic AS ctf
# install pwntools
RUN apt-get update -y\
&& apt-get install python3 python3-pip python3-dev libssl-dev libffi-dev -y\
&& python3 -m pip install --upgrade pip\
&& python3 -m pip install --upgrade pwntools==4.8.0b0

# install angr
RUN apt-get install python3-dev libffi-dev build-essential virtualenvwrapper -y\
&& pip install angr

# install z3
RUN pip install z3-solver

# install one gadget
RUN apt-get install ruby -y
RUN gem install one_gadget

# install qemu
RUN apt-get install qemu-efi qemu-user -y

# install arm libc
RUN apt-get install libc6-armhf-cross libc6-arm64-cross gdb-multiarch qemu-system-arm -y

# install r888800009/CTF-tool/
RUN apt-get install xonsh -y
RUN git clone https://github.com/r888800009/CTF-tool/

# install r888800009/dotfile/
RUN apt-get install zsh sudo -y
RUN git clone https://github.com/r888800009/dotfile/ ~/dotfile
RUN cd ~/dotfile ; bash setup_zsh.sh
RUN zsh ~/.zshrc

# install qiling
RUN pip install qiling

# install proxychains
RUN apt-get install proxychains -y

# seccomp
RUN apt-get install gcc ruby-dev libseccomp-dev -y
RUN gem install seccomp-tools

RUN git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh && pip install r2pipe

RUN chsh -s /bin/zsh

# strace
RUN apt-get install strace ltrace -y

# nc
RUN apt-get install netcat-traditional -y

# ROP
RUN pip install --upgrade --force-reinstall ROPgadget

CMD ["zsh"]
