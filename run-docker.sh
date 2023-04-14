#!/bin/bash

docker run -it --rm -e DISPLAY=$DISPLAY --ipc host -v /tmp/.X11-unix:/tmp/.X11-unix -v $PWD:/home/angr/pwd angr/angr-management "$@"
