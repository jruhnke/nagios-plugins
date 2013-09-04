#!/bin/bash
#
# Copyright 2013 Jay Ruhnke
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#
# Nagios check script for certificate expiration
#
###
#
# usage :./check_certificate.sh -h host -p port [-c crit] [-w warn [-v] [-t seconds]]
#
# OPTIONS:
#    -h  Host
#    -p  Port
#    -c  Critical alarm when certificate is N hours from expiring (Optional) (default: 72)
#    -w  Warning alarm when certificate is N hours from expiring (Optional) (default: 120)
#    -v  Use the -v flag for verbose output (Optional)
#    -t  Timeout (Optional) (default: 30 seconds)
#
###

function usage() {
  echo -e "usage :$0 -h host -p port [-c crit] [-w warn] [-v] [-t seconds]"
  echo -e "\nOPTIONS:"
  echo -e "\t-h  Host"
  echo -e "\t-p  Port"
  echo -e "\t-c  Critical alarm when certificate is N hours from expiring (Optional) (default: 72)"
  echo -e "\t-w  Warning alarm when certificate is N hours from expiring (Optional) (default: 120)"
  echo -e "\t-v  Use the -v flag for verbose output (Optional)"
  echo -e "\t-t  Timeout (Optional) (default: 30 seconds)"
}

function timeout () 
{ 
    local timeout=$1; shift; 

    "$@" <&0 & 
    cmd_pid=$!; 

    ( for (( i=timeout; i ; i-- )) 
      do 
        kill -0 $cmd_pid >& /dev/null || exit; 
        sleep 1; 
      done; 
      kill -0 $cmd_pid >& /dev/null || exit; 
      echo $(date): "$@" timed out after $timeout seconds 
      kill -TERM $cmd_pid >& /dev/null 
    ) 2> /dev/null 
    wait $cmd_pid 
}

function fetchCertificate() {
    hostAndPort=$1:$2
    if [ -f /tmp/cert_check.log ]; then
        /bin/rm /tmp/cert_check.log
    fi

    if [ -z "$TIMEOUT" ]; then
        TIMEOUT=30
    fi

    timeout $TIMEOUT openssl s_client -connect "$hostAndPort" -showcerts -prexit > /tmp/cert_check.log 2>&1
}

function printMsg () {
    if [ ! "$VERB" ]; then
        echo -e "$1"
    elif [ "$VERB" ]; then
        certSub=`openssl x509 -inform PEM -in /tmp/cert_check.log -text | grep "Subject: " | sed 's/^ *//g'`
        certSN=`openssl x509 -inform PEM -in /tmp/cert_check.log -text | grep "Serial Number: " | sed 's/^ *//g'`
        certIss=`openssl x509 -inform PEM -in /tmp/cert_check.log -text | grep "Issuer: " | sed 's/^ *//g'`
        echo -e "$1\n\t$certSub\n\t$certSN\n\t$certIss"
    fi
}

function unknownError() {
    printMsg "UNKNOWN: $1"
    exit 3
}

function criticalError() {
    printMsg "CRITICAL: $1"
    exit 2
}

function warnMsg() {
    printMsg "WARNING: $1"
    exit 1
}

function okMsg() {
    printMsg "OK: $1" 
}

function processCert() {
    if [ -z "$1" ]; then
        WARN=120
    fi

    if [ -z "$2" ]; then
        CRIT=72
    fi

    dt1=`openssl x509 -inform PEM -in /tmp/cert_check.log -text | grep "Not After" | sed 's/Not After : //g' | sed 's/^ *//g'`

        if [ -n "$dt1" ]; then
            OS=`uname -s`
            
            # Compute the seconds since epoch for date 1
            if [ "$OS" == "Darwin" ]; then
                t1=`/bin/date -j -f "%b %d %T %Y %Z" "$dt1" "+%s"`
            else
                t1=`/bin/date -d "$dt1" "+%s"`
            fi
        else
            unknownError "No certificate"
        fi
    
        # Compute the seconds since epoch for date 2
        t2=`/bin/date +%s`

        # Compute the difference in dates in seconds
        let "tDiff=$t1-$t2"
        # Compute the approximate hour difference
        let "hDiff=$tDiff/3600"

        if [ $hDiff -le 0 ]; then
            criticalError "The certificate has expired $hDiff ago on $dt1."
        else
            if [ $hDiff -le $WARN ]; then
                warnMsg "The certificate is about to expire in $hDiff hours on $dt1."
            fi

            if [ $hDiff -le $CRIT ]; then
                criticalError "The certificate is about to expire in $hDiff hours on $dt1."
            fi

            okMsg "The certificate is good for another $hDiff hours until $dt1."
       fi

    /bin/rm /tmp/cert_check.log
}

function run() {
    fetchCertificate "$HOST" "$PORT"

    l1=`head -1 /tmp/cert_check.log`

    case "$l1" in
        "gethostbyname failure")
            unknownError "$l1"
            ;;
        "connect: Connection refused")
            unknownError "$l1"
            ;;
        "write:errno=54")
            unknownError "no peer certificate available"
            ;;
        "write:errno=104")
            unknownError "no peer certificate available"
            ;;
        "no port defined")
            criticalError "$l1"
            ;;
        *)
            processCert "$WARN" "$CRIT"
            ;;
    esac
}

while getopts "?h:p:c:w:vt:" OPTION; do
  case $OPTION in
    h)
      HOST=$OPTARG
    ;;
    p)
      PORT=$OPTARG
    ;;
    c)
      CRIT=$OPTARG
    ;;
    w)
      WARN=$OPTARG
    ;;
    v)
      VERB=true
    ;;
    t)
      TIMEOUT=$OPTARG
    ;;
    ?)
      usage
      exit 0
    ;;
  esac
done

if [ -z "$HOST" -o -z "$PORT" ]; then
    usage
    exit 0
fi

run

exit 0
