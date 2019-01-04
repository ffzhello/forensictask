#!/bin/bash
kill -9 $(ps -ef | grep forensictask | gawk '$0 !~/grep/ {print $2}' |tr -s '\n' ' ')