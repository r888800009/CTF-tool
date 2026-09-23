# Ubuntu 18.04/20.04 ship older Python versions embedded in GDB.
ARG VERSION=22.04
FROM ubuntu:${VERSION} AS basic
ARG VERSION

RUN apt-get update -y \
&& apt-get install gcc gdb curl vim python3 cmake make sudo file gawk bison patchelf -y

ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8
ENV PIP_BREAK_SYSTEM_PACKAGES=1

RUN apt-get -y install locales \
&& sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
&& locale-gen --no-purge en_US.UTF-8

RUN apt-get install tmux git build-essential -y

# Install PEDA, pwndbg and GEF together. The installer's gdbinit provides
# init-peda, init-pwndbg and init-gef so the debugger can be switched.
RUN case "${VERSION}" in \
    16.04|16.10|17.04|17.10|18.04|18.10|19.04|19.10|20.04|20.10|21.04|21.10) \
        git clone https://github.com/apogiatzis/gdb-peda-pwndbg-gef /tmp/gdb-tools && \
        sed -i 's#git clone https://github.com/hugsy/gef.git ~/gef#git clone --branch 2024.06 https://github.com/hugsy/gef.git ~/gef#' /tmp/gdb-tools/install.sh && \
        cd /tmp/gdb-tools && ./install.sh ;; \
    *) \
        git clone https://github.com/apogiatzis/gdb-peda-pwndbg-gef && \
        cd gdb-peda-pwndbg-gef && ./install.sh ;; \
    esac

FROM basic AS ctf
# install pwntools
RUN apt-get update -y\
&& apt-get install python3 python3-pip python3-dev libssl-dev libffi-dev -y\
&& python3 -m pip install --upgrade pwntools

# install angr
RUN apt-get install python3-dev libffi-dev build-essential virtualenvwrapper -y\
&& python3 -m pip install angr

# install one gadget
RUN apt-get install ruby -y
# Newer one_gadget releases require Ruby >= 3.3. Use the latest release when
# the selected Ubuntu image provides a compatible Ruby, otherwise use the
# newest one_gadget release compatible with older Ubuntu images.
RUN if ruby -e 'exit(RUBY_VERSION >= "3.3")'; then \
        gem install one_gadget; \
    else \
        gem install one_gadget -v 1.8.1; \
    fi

# install qemu
RUN apt-get install qemu-user -y

# install arm libc
RUN apt-get install libc6-armhf-cross libc6-arm64-cross gdb-multiarch qemu-system-arm -y

# install r888800009/CTF-tool/
RUN apt-get install xonsh -y
RUN git clone https://github.com/r888800009/CTF-tool/ \
    && cd CTF-tool && python3 instal_gdb_toolbox.py

# install r888800009/dotfile/
RUN apt-get install zsh sudo -y
RUN git clone https://github.com/r888800009/dotfile/ ~/dotfile
RUN cd ~/dotfile ; bash setup_zsh.sh
RUN zsh ~/.zshrc

# install qiling
RUN python3 -m pip install qiling

# install proxychains
RUN apt-get install proxychains -y

# seccomp
RUN apt-get install gcc ruby-dev libseccomp-dev -y
RUN if ruby -e 'exit(RUBY_VERSION >= "3.1")'; then \
        gem install seccomp-tools; \
    else \
        gem install seccomp-tools -v 1.6.1; \
    fi

RUN git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh && python3 -m pip install r2pipe

RUN chsh -s /bin/zsh

# strace
RUN apt-get install strace ltrace -y

# nc
RUN apt-get install netcat-traditional -y

# ROP
RUN python3 -m pip install --upgrade --force-reinstall ROPgadget

# ropr
RUN apt-get update -y \
&& apt-get install curl -y \
&& curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init \
&& sh /tmp/rustup-init -y --profile minimal --default-toolchain stable \
&& /root/.cargo/bin/cargo install ropr --version 0.2.26
ENV PATH=/root/.cargo/bin:$PATH

CMD ["zsh"]
