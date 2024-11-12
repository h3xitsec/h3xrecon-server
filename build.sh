#!/usr/bin/env bash
trap 'echo Exited!; exit;' SIGINT SIGTERM
unset DOCKER_HOST
echo "======================================="
echo " Building H3xrecon Server Docker Image "
echo "======================================="

docker buildx build --output type=docker --file ./src/docker/h3xrecon/Dockerfile --platform linux/amd64 --tag h3xrecontest/h3xrecon:latest ./src/docker/h3xrecon/

echo "======================================="
echo "    Docker image built successfully!   "
echo "======================================="
