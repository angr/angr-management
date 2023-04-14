#!/bin/bash

function check ()
{
    listen=`lsof -n -i:6000 | grep LISTEN`
    if [ "$listen" = "" ]
    then
        pass=0
    else
        pass=1
    fi
}

function listen ()
{
    defaults write org.x.X11 nolisten_tcp 0
    xhost + $ip
}

ip=`ifconfig en0 | grep inet | awk '$1=="inet" {print $2}'`

check
if [ "$pass" -eq "0" ]
then
    listen
fi

docker run -it --rm -e DISPLAY=$ip:0 --ipc host -v /tmp/.X11-unix:/tmp/.X11-unix -v $PWD:/home/angr/pwd angr/angr-management "$@"
