#!/bin/bash

# Copyright (c) 2012 The Internet Infrastructure Foundation (.SE). All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# queue handling vars
NUM=0
QUEUE=""
MAXPROCS=80

# die function
function die() {
    echo "$*" 1>&2
    exit 1
}

# input
function createoutdir {
    DATE=`date +%Y-%m-%d`
    OUTDIR="${DATE}"
    mkdir $OUTDIR || die "mkdir failed with status $?"
}


function echoqueue {
    for PID in $QUEUE
    do
	echo -n "$PID "
	done
    echo
}

function queue {
    QUEUE="$QUEUE
    $1"
    NUM=$(($NUM+1))
    #echo -n "QUEUE ";echoqueue
}

function dequeue {
    OLDDEQUEUE=$QUEUE
    QUEUE=""
    for PID in $OLDDEQUEUE
    do
	if [ ! "$PID" = "$1" ] ; then
	    QUEUE="$QUEUE
    $PID"
	    fi
	done
    NUM=$(($NUM-1))
#    echo -n "DEQUEUE ";echoqueue
}

function checkqueue {
    OLDCHQUEUE=$QUEUE
    for PID in $OLDCHQUEUE
    do
	if [ ! -d /proc/$PID ] ; then
	    dequeue $PID
	    fi
	done
#    echo -n "CHECKQUEUE ";echoqueue
}

function runqueue {
    cat $INPUTFILE | while read domain; do
    #COMMAND TO SPAWN
	echo $domain
	sh -c "./burnds.pl -n $domain > $OUTDIR/$domain" &

    #COMMAND TO SPAWN STOP
	PID=$!
	queue $PID
	
	while [ $NUM -ge $MAXPROCS ] # MAX PROCESSES
	do
	    checkqueue
	    sleep 1
	done
    done    
}

if [ -n "$1" ] ; then
    INPUTFILE=$1
    createoutdir
    runqueue
else
    echo "missing argument(s)"
    echo "usage:"
    echo "${0} <list.txt>"
fi
