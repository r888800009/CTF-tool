#!/bin/bash
ubuntu_versions=(
  "16.04"
  "16.10"
  "17.04"
  "17.10"
  "18.04"
  "18.10"
  "19.04"
  "19.10"
  "20.04"
  "20.10"
  "21.04"
  "21.10"
  "22.04"
  "22.10"
)


if [ -z "$1" ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 16.04"
  # show all versions
  for version in "${ubuntu_versions[@]}"; do
    echo "  $version"
  done
  exit 1
fi

docker_name=ctf_ubuntu_$1

docker build . -t $docker_name --target ctf --build-arg VERSION=$1

echo "Run the following command to run the container:"
echo "  docker run --rm -it -v "'$(pwd)'":/work $docker_name"

