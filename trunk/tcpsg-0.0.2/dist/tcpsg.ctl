#/bin/sh

processfind()
{
  if [ ${#} -ne 1 ]
    then
      return 0;
  fi

  /bin/ps -auwx | /usr/bin/awk '{print $11}' | /bin/grep -q ${1};
  GREPFLAG=${?};

  return ${GREPFLAG};
}

#
# Usage: ./tcpsg.ctl start
#        ./tcpsg.ctl stop
#

#
# Check action by the number of arguments

#
if [ ${#} -ne 1 ]
  then
    /bin/echo "Usage:";
    /bin/echo "${0} start";
    /bin/echo "${0} stop";

    exit ${?};
fi

#
# Get action from the first argument
#
ACTION=${1};

#        
# Check for function library
#
RUNNING=0;
if processfind "tcpsg"
  then
    RUNNING=1;
fi;

#
# Follow the action
#
case "${ACTION}" in
#
# START
#
  start)
#
# If it's already running, no need to start.
#
    if [ ${RUNNING} -ne 0 ]
      then
        /bin/echo "TcpSg has already been started."

      exit 1;
    fi;
    /usr/sbin/tcpsg
    exit ${?};
    ;;
# 
# STOP
#
  stop)
# 
# If it's not running, no need to stop.
#
    if [ ${RUNNING} -eq 0 ]
      then
        /bin/echo "TcpSG is not running."
      exit 1;
    fi;
# 
# Stop system processes
#
    /usr/bin/killall tcpsg;

    exit ${?};
    ;;
# 
# OTHERS
#
  *)
    /bin/echo "Usage: ${0} {start|stop}"

    exit ${?};
esac;




