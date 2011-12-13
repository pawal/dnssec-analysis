#!/bin/bash

# queue handling vars
NUM=0
QUEUE=""
MAXPROCS=40

# die function
function die() {
    echo "$*" 1>&2
    exit 1
}

# input
function createoutdir {
    DATE=`date +%Y-%m-%e`
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
