#!/usr/bin/env python
import sys
import os

ubuntu_versions = ["16.04", "16.10", "17.04", "17.10", "18.04", "18.10", "19.04", "19.10", "20.04", "20.10", "21.04", "21.10", "22.04", "22.10"]
def print_help():
    print("Usage: python start_docker.py <ubuntu_version>")
    print("Available versions: " + '|'.join(ubuntu_versions))
    sys.exit(1)

if len(sys.argv) < 2:
    print_help()

ubuntu_version = sys.argv[1]
script_path = './pwn_docker/setup_docker.sh'

if ubuntu_version not in ubuntu_versions:
    print_help()

# check if docker is installed
if os.system('docker -v') != 0:
    print("Docker is not installed")
    sys.exit(1)

# check if docker image exists
docker_name = 'ctf_ubuntu_' + ubuntu_version
if os.system('docker images -q ' + docker_name) != 0:
    print("Docker image " + docker_name + " not found, building...")
    current_path = os.getcwd()
    os.chdir('./pwn_docker')
    cmd = f'./setup_docker.sh {ubuntu_version}'
    if os.system(cmd) != 0:
        print("Build failed")
        sys.exit(1)
    os.chdir(current_path)

# run docker
os.system(f'docker run --net="host" --privileged --rm -it -v "$(pwd)":/work {docker_name}')
