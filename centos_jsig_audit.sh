#!/bin/bash
##### UNCLASSIFIED ##########
# Written by Charlie Todd (ctodd@ball.com)
# Copyright 2019 Ball Aerospace
# Written under contract to the U.S. Government
# Contract FA8650-16-D06582
# LICENSE - this is commercial software and may only be used with permission
# Permission to use and redistribute is given to the U.S. Government

# Purpose: Satisfy auditing requirements on standalone Linux systems
#   Note that STIG-compliant auditing must be configured for these reports
#   to have meaningful data.
# Description:
#   If the user has sudo privilege on the system to execute the aureport command,
#   then "sudo aureport <options>" is run multiple times to produce a report
#   in the local folder.  If no reports exist, then an audit review is done
#   for the last $daysBack days.  If successful audit review reports are
#   in the same folder, then this audit review will be set to start from
#   the moment that last report was first started.  This should provide
#   continuous coverage in the event that an irregular schedule is followed.

reportFileOnly="$(date +%Y%m%d_%H%M%S)-${HOSTNAME/\.*/}-audit_report.txt"
reportLocation="$(dirname $0)"
reportFile="$reportLocation/$reportFileOnly"
daysBack=7
ME="${SUDO_USER:-$USER}"

# stop on script errors since it is a bug
#set -e

function checkLoggedInAsRoot {
   if [ "$USER" == "root" -a -z "$SUDO_USER" ]; then
       echo "ALERT: This tools should be run as you. " 1>&2
       echo "       Do not login in such a way that you use the root password." 1>&2
       echo "       Exiting this script." 1>&2
       echo "ALERT: audit review aborted because the user did not log in as themselves" > $reportFile
       exit 2
   fi
}

checkLoggedInAsRoot

# if the user has sudo privileges, return 0.  Otherwise, return a non-zero value
# If they fail to authenticate, that also counts against them
function checkSudoPrivileges {
   allowed=$(/bin/sudo --prompt="Checking to see if you have sudo privileges.
[sudo] password for ${USER}: " --list )
   return $?
}

function AUREPORT {
   if [ $(whoami) != "root" ]; then
       /bin/sudo /usr/sbin/aureport $*
   else
       aureport $* 
   fi
   return $?
}

function AUSEARCH {
   if [ $(whoami) != "root" ]; then
       /bin/sudo /usr/sbin/ausearch $*
   else
       ausearch $* 
   fi
   return $?
}

# Write output to the screen and a logfile
function reportLine {
   if [ $# -gt 0 ]; then
       echo "$*" >> $reportFile
   else
       cat >> $reportFile
   fi
}

function reportAndScreenLine {
   if [ $# -gt 0 ]; then
       echo "$*" | tee -a $reportFile
   else
       cat | tee -a $reportFile
   fi
}

function getSudoOrExit {
   checkSudoPrivileges
   if [ $? -ne 0 ]; then
      reportAndScreenLine "You have no sudo privileges, or don't know the password.  Exiting."
      exit 1
   fi
}

function getNewestReportDate {
   # returns a string in aureport friendly time format MM/DD/YYYY HH:MM:ss
   # unless --fileSafe is a parameter, in which case it is YYYYMMDD_hhmmss
   # note that newest file is this log file, so the second newest
   dateFormat="%m/%d/%Y %H:%M:%S"
   if [ "$1" == "--fileSafe" ]; then
       dateFormat="%Y%m%d_%H%M%S"
   fi
   files=$(cd "$reportLocation";
       /bin/ls -1t *-${HOSTNAME/\.*/}-audit_report.txt 2>/dev/null)
   for report in $files; do
       tail -1 $report | grep --silent "Audit Review Complete"
       if [ $? -eq 0 ]; then
           reportLine "Setting the audit start time from $report"
           fileDate=$(stat -c %Z $report) ; # time since change in epoch seconds
           auditDate=$(date -d @$fileDate +"$dateFormat")
           echo "$auditDate"
	   return
       else
           :
           #reportLine "Ignoring this report which never completed: $report"
       fi
   done
   #output nothing if no reports exist
}

# getAuditStart provides an ausearch/aureport friendly date
# either starting at the last report or $daysBack days ago (default 7 days)
# Format looks like "mm/dd/yyyy hh:mm:ss"
function getAuditStart {
   startDate=$(getNewestReportDate) 
   if [ -z "$startDate" ]; then
       startDate=$(date -d "$daysBack days ago" +"%m/%d/%Y %H:%M:%S")
   fi
   echo "$startDate"
}

# getAuditStartFileSafe provides an ausearch/aureport friendly date
# either starting at the last report or $daysBack days ago (default 7 days)
# Format looks like "yyyymmdd_hhmmss"
function getAuditStartFileSafe {
   startDate=$(getNewestReportDate --fileSafe) 
   if [ -z "$startDate" ]; then
       startDate=$(date -d "$daysBack days ago" +"%Y%m%d_%H%M%S")
   fi
   echo "$startDate"
}
function getScriptChecksum {
   cksum=$(cat $0 | sha256sum )
   lastModified=$(stat -c%y $0)
   thisPath=$(dirname $0)
   if [ "$thisPath" == "." ]; then
      thisPath=$(pwd)
   fi
   reportAndScreenLine "This program:        ${thisPath}/$(basename $0)"
   reportAndScreenLine "This program checksum:     $cksum (SHA256)"
   reportAndScreenLine "This program lastmodified: $lastModified"
}

function failAndExit {
   reportAndScreenLine "[ERROR]: There were problems with the last command.  Exit code $?"
   reportAndScreenLine "         The audit review is **NOT COMPLETE**.  Exiting."
   exit 1
}


function quickAuditCheck {
   failures=0
   service auditd status 2>/dev/null >/dev/null
   if [ $? -ne 0 ]; then
      echo "ERROR: auditd is not running on this host"
      failures=$[ $failures + 1 ]
   fi
   numRecords=$(sudo cat /etc/audit/audit.rules | wc -l)
   if [ -z "$numRecords" -o "$numRecords" -lt 100 ]; then
      echo "ERROR: auditd is not adequately configured on this host"
      echo "       please apply the stig-disa-7 profile with oscap"
      failures=$[ $failures + 1 ]
   fi
   return $failures
}

# return 0 if the file watch is in place with the specified permissions
function auditRuleCheckWatch {
   auditctlOutput="$1"
   file="${2:-/var/log/audit/audit.log}"
   perm="${3:-ra}"
   echo "$auditctlOutput" |egrep --silent -e "^-w \"?$file\"? -p $perm" 
   res=$?
   if [ $res -ne 0 ]; then
      reportLine "=== WARNING: $file is not being watched by the audit daemon"
   fi
   return $res
}
# return 0 if auditing is configured to watch 
# the audit log files
function checkAuditLogWatch {
   actl=$(sudo auditctl -l)
   if [ -n "${actl}" ]; then
      {
          auditRuleCheckWatch "${actl}" /var/log/audit/audit.log && \
          auditRuleCheckWatch "${actl}" /var/log/secure && \
          auditRuleCheckWatch "${actl}" /var/log/tallylog && \
          auditRuleCheckWatch "${actl}" /var/log/lastlog 
      } || {
          sampleFile="01-security_log.rules"
          cat > "$sampleFile" << EOF
# meet JSIG AU-2.a.9 - Audit and security relevant log data accesses
-w /var/log/secure -p ra -k security_log
-w /var/log/lastlog -p ra -k security_log
-w /var/log/tallylog -p ra -k security_log
-w /var/log/wtmp -p ra -k security_log
-w /var/log/audit/audit.log -p ra  -k security_log
EOF
          reportAndScreenLine "=== ERROR: audit is not configured to fully"
          reportAndScreenLine "===        record AU-2, specifically AU-2.a.9"
          reportAndScreenLine "===        Copy $sampleFile to /etc/audit/rules.d"
          reportAndScreenLine "===        and restart the audit daemon with"
          reportAndScreenLine "===          sudo mv $sampleFile /etc/audit/rules.d && sudo service auditd restart"
          reportAndScreenLine "=== Quick audit configuration check complete "
          return 1
      }
   else
      reportAndScreenLine "WARNING: Could not get a list of current audit rules"
      return 1
   fi
   return 0
}

function getUsersWithBurnPrivileges {
   opticalMedia=$(/bin/ls -1 /dev/sr[0-9]*)
   if [ -n "$opticalMedia" ]; then
      ( for device in $opticalMedia; do
         deviceGroup=$(stat --printf "%G" $device)
         usersInGroup=$(getent group $deviceGroup | cut -d: -f4)
         echo "$usersInGroup" | sed -e 's/,/\n/g'
      done ) | sort | uniq
   fi 
}

function checkMkisofs {
   if [ -n "$(rpm -qa mkisofs)" ]; then
      reportLine          "Note:             this system has tools to build ISOs, so"
      reportLine          "                  files could be exfiltrated this way as a bundle."
      auditRuleCheckWatch $(which mkisofs)
      if [ $? -eq 0 ]; then
         reportLine          "Here are all the times that $(which mkisofs) was called"
         AUSEARCH $auditDateOptions --format text --file $(which mkisofs) | reportLine
      else
         sampleFile="02-media.rules"      
         # meet JSIG AU-2.a.9 - Audit and security relevant log data accesses
         echo "# === improve JSIG AU-2.a.3 Export/Write to digital media " 
         echo "# === improve JSIG AU-2.a.4 Import from digital media" 
         echo "-w $(which mkisofs) -p x -k media" >> $sampleFile
         reportAndScreenLine "Suggestion:       create a watch on $(which mkisofs) like"
         reportAndScreenLine "                  by copying $sampleFile to /etc/audit.d/rules.d"
         reportAndScreenLine "                     sudo mv $sampleFile /etc/audit/rules.d && sudo service auditd restart"
      fi
   fi
}

# if the wodim RPM is installed, someone determined that optical media 
# reading and writing were permissible.  If there were installed recently,
# of if this is a new system, we have not added the auditing of those 
# programs to this system and/or report, so we provide a sample file
# that can be added to /etc/audit.d/rules.d.  Subsequent runs will
# report on usage of those executables.  
function checkWodim {
   if [ -n "$(rpm -qa wodim)" ]; then
      reportLine          "Note:             this system has tools to read or write from media."
      reportLine          "                  files could be exfiltrated this way"
      wodimExes=$( rpm -ql wodim | egrep "/.*bin.*/" )
      ### TODO: put this in a function and finish it with auditRuleCheck
      auditRuleCheckWatch $(which mkisofs)
      if [ $? -eq 0 ]; then
         reportLine          "Here are all the times that wodim (CD burning) executables "
         reportLine          "were called but note that we search one executable at a time,"
         reportLine          "so the results are not sorted by time."
         for exe in $wodimExes; do
            AUSEARCH $auditDateOptions --format text --file $exe | reportLine
         done
      else
         sampleFile="02-media.rules"      
         echo "# === improve JSIG AU-2.a.3 Export/Write to digital media "  >> $sampleFile
         echo "# === improve JSIG AU-2.a.4 Import from digital media"  >> $sampleFile
         for exe in $wodimExes; do
            echo "-w $wodimExes -p x -k media" >> $sampleFile
         done
         reportAndScreenLine "Suggestion:       create a watch on CD Burning applications"
         reportAndScreenLine "                  by copying $sampleFile to /etc/audit.d/rules.d"
         reportAndScreenLine "                     sudo mv $sampleFile /etc/audit/rules.d && sudo service auditd restart"
      fi
   fi
}

function checkUnsupportedUnset {
   filesWith=$(sudo bash -c "grep --files-with-matches '=unset ' /etc/audit/rules.d/* ")
   if [ -n "$filesWith" ]; then
      reportAndScreenLine "WARNING: This OS does not support audit rules that ask for"
      reportAndScreenLine "         'unset' UIDs.  This can cause audit rules to go unparsed."
      reportAndScreenLine "         Please run these commands to remove those rules and then"
      reportAndScreenLine "         restart auditing."
      cat | reportAndScreenLine << EOF
      sudo bash -c "grep --files-with-matches '=unset ' /etc/audit/rules.d/* | xargs sed -i.bak 's/=unset/=-1/' "
      service auditd restart 
EOF
      sleep 10
   fi
}
##############################################################################
##############################################################################
##############################################################################
##############################################################################
reportAndScreenLine "=================================================" 
reportAndScreenLine "Audit review of:     ${HOSTNAME} on $(date)" 
reportAndScreenLine "Review conducted by: ${ME}"
reportAndScreenLine "This report:         $reportFileOnly" 
auditStart=$(getAuditStart)
auditEnd=$(date +"%m/%d/%Y %H:%M:%S")
archiveStart=$(getAuditStartFileSafe)
auditArchiveFile="$reportLocation/${HOSTNAME}-audit_archive-${archiveStart}_to_$(date +%Y%m%d_%H%M%S).log"
reportAndScreenLine "Earliest audit date: $auditStart" 
reportAndScreenLine "Latest audit date:   $auditEnd" 
reportAndScreenLine "Archive audit file:  $auditArchiveFile"
getScriptChecksum
reportAndScreenLine "=================================================" 
reportAndScreenLine "" 

getSudoOrExit

auditDateOptions=" -ts $auditStart -te $auditEnd"
commonAuditOptions=" $auditDateOptions -i"

reportAndScreenLine "================================================="
reportAndScreenLine "=== Quick audit configuration check "
quickAuditCheck | reportLine || failAndExit
checkAuditLogWatch || sleep 15
reportAndScreenLine "=== Quick audit configuration check complete "
reportLine          "" 


reportAndScreenLine "================================================="
reportAndScreenLine "=== Archiving the audit records for integrity and to "
reportAndScreenLine "=== minimize traffic on the audit log"
AUSEARCH $auditDateOptions --raw > $auditArchiveFile
if [ $? -eq 0 ]; then
   reportAndScreenLine "=== Archiving complete"
   auditDateOptions="$auditDateOptions -if $auditArchiveFile"
   trap "echo \"Removing $auditArchiveFile on break\"; rm $auditArchiveFile; exit 2" 2 3 4 5 6 7 8 9 10 12 13 14
else 
   freeSpace=$(df -h --output=avail $(dirname $auditArchiveFile))
   reportAndScreenLine "=== Archiving FAILED.  Exiting. $freeSpace left in folder."
   failAndExit 
fi

reportAndScreenLine "================================================="
reportAndScreenLine "=== AUDIT REPORT: Summary "
reportAndScreenLine "=== Description:  A brief overview of events "
AUREPORT $commonAuditOptions | reportLine || failAndExit
reportLine          "=== AUDIT REPORT: Summary " 
reportLine          "" 


reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Anomoly Events "
reportAndScreenLine "=== Description:  Strange events that should rarely occur "
AUREPORT   --anomaly $commonAuditOptions | reportLine || failAndExit
reportLine          "=== AUDIT REPORT: Anomoly Events " 
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: User Authorizations (FAILED) "
reportAndScreenLine "=== Description:  all events that show an account validation was"
reportAndScreenLine "===               attempted, but failed"
reportAndScreenLine "=== JSIG:         AU-2.a.1.(1) Logons (Failure)"
AUREPORT --auth --failed $commonAuditOptions | reportLine || failAndExit
reportLine          "=== AUDIT REPORT: User Authorizations (FAILED)" 
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Login/Logout (SUCCESS)"
reportAndScreenLine "=== Description:  All events that show an account validation was"
reportAndScreenLine "===               attempted, and succeeded"
reportAndScreenLine "=== Note:         An unsuccessful logout is one that was"
reportAndScreenLine "===               forced during a reboot"
reportAndScreenLine "=== JSIG:         AU-2.a.1.(1) Logons (Success)"
reportAndScreenLine "=== JSIG:         AU-2.a.1.(2) Logouts (Success/Failure)"
#AUREPORT --auth --success $commonAuditOptions | reportLine || failAndExit
AUSEARCH $auditDateOptions --raw | aulast
reportLine          "=== AUDIT REPORT: Login/Logout (SUCCESS)" 
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Digital Media"
reportAndScreenLine "=== Description:  All events for portable media, be it"
reportAndScreenLine "===               mount, unmount, read, or write"
reportAndScreenLine "=== Note:         This audit requirement is difficult to"
reportAndScreenLine "===               satisfy under Linux with the native audit"
reportAndScreenLine "===               system.  If user-mountable drives are"
reportAndScreenLine "===               configured, your administrator should have"
reportAndScreenLine "===               auditd configured to watch those paths and"
reportAndScreenLine "===               this script modified to support it."
reportAndScreenLine "=== JSIG:         AU-2.a.3 Export/Write to digital media [partial]" 
reportAndScreenLine "=== JSIG:         AU-2.a.4 Import from digital media [partial]" 
reportLine          "Mounts of any filesystem"
reportLine          "------------------------"
AUSEARCH $auditDateOptions --format text --syscall mount| reportLine
reportLine          "Unmounts of any filesystem (compare to list above)"
reportLine          "--------------------------------------------------"
AUSEARCH $auditDateOptions --format text --file /bin/mount| reportLine
reportLine          ""
reportLine          "Note that no file read or device writing was audited on this system" 
reportLine          "beyond that normally recorded everywhere on the system."
### if these RPMs are installed, recommend that audit rules be put in place
### if they aren't
checkMkisofs
checkWodim
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Local account management"
reportAndScreenLine "=== Description:  Users and groups added, deleted, or"
reportAndScreenLine "===               modified (Success/Failure)"
reportAndScreenLine "=== JSIG:         AU-2.a.5.(1) User add, delete, modify, disable (Success/Failure)" 
reportAndScreenLine "=== JSIG:         AU-2.a.5.(2) Group add, delete, modify, disable (Success/Failure)" 
AUREPORT --mods $commonAuditOptions | reportLine || failAndExit
reportLine          "=== AUDIT REPORT: Local account management" 
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Configuration Changes (FAILED)"
reportAndScreenLine "=== Description:  Failed attempts to change files called out"
reportAndScreenLine "===               in the audit configuration"
reportAndScreenLine "=== JSIG:         AU-2.a.6.(1) Security or audit policy changes (Failure)" 
reportAndScreenLine "=== JSIG:         AU-2.a.6.(2) Configuration changes (Failure)" 
AUREPORT --config --failed $commonAuditOptions | reportLine || failAndExit
reportLine          "=== AUDIT REPORT: Configuration Changes (FAILED)"
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Configuration Changes (SUCCESS)"
reportAndScreenLine "=== Description:  Successful changes made to files called out"
reportAndScreenLine "===               in the audit configuration"
reportAndScreenLine "=== JSIG:         AU-2.a.6.(1) Security or audit policy changes (Success)" 
reportAndScreenLine "=== JSIG:         AU-2.a.6.(2) Configuration changes (Success)" 
AUREPORT --config --success$commonAuditOptions | reportLine || failAndExit
reportLine          "=== AUDIT REPORT: Configuration Changes (SUCCESS)"
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Login directly as root"
reportAndScreenLine "=== Description:  Detect when someone logs into the "
reportAndScreenLine "===               system as root (Success/Failure)"
reportAndScreenLine "=== JSIG:         AU-2.a.7 Admin or root-level access (Success/Failure)" 
uid0Users=$(awk 'BEGIN{FS=":"} $3 == "0" {print $1}' /etc/passwd)
if [ "$uid0Users" != "root" ]; then
   reportAndScreenLine "=== WARNING: UID 0 resolves to users other than \"root\": $(echo $uid0Users) "
   reportAndScreenLine "===          This script only checks for the \"root\" user."
fi
AUREPORT --login $commonAuditOptions | awk 'NR<6 {print} NR>1 && / root .*tty/ { print }' \
		| reportLine || failAndExit
reportLine          "=== AUDIT REPORT: Login directly as root" 
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Privilege/role escalation"
reportAndScreenLine "=== Description:  Commands run by a user when they"
reportAndScreenLine "===               have taken on privileges"
reportAndScreenLine "=== Note:         Noisy commands issued during login are filtered out"
reportAndScreenLine "=== JSIG:         AU-2.a.8 Privilege/role escalation (Success/Failure)" 
AUREPORT --key privileged $commonAuditOptions --format text | \
		grep -v ' root, successfully executed /usr/sbin/unix_chkpwd' | \
		reportLine || failAndExit
reportLine          "=== AUDIT REPORT: Privilege/role escalation"
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Security relevant log data access (FAILURE)"
reportAndScreenLine "=== Description:  Report failed attempts to read the"
reportAndScreenLine "===               the audit log or the security log"
reportAndScreenLine "=== JSIG:         AU-2.a.9 Audit and security relevant log data access (Failure)" 
AUSEARCH  --failure $auditDateOptions --file /var/log/audit --file /var/log |\
		 reportLine || failAndExit
reportLine          "=== AUDIT REPORT: Security log data access"
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Security relevant log data access (SUCCESS)"
reportAndScreenLine "=== Description:  "
reportAndScreenLine "=== JSIG:         AU-2.a.9 Audit and security relevant log data access (Success/Failure)" 
#AUSEARCH  --success $auditDateOptions | reportLine || failAndExit
#AUSEARCH  --success $auditDateOptions | reportLine || failAndExit
reportAndScreenLine "=== WARNING: Not implemented yet"
reportLine          "=== AUDIT REPORT: Security log data access"
reportLine          "" 

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: System start/shutdown"
reportAndScreenLine "=== Description:  Show the system booting, controlled shutdowns,"
reportAndScreenLine "===               runlevel changes (anything other than runlevel-3"
reportAndScreenLine "===               means that problems happened during boot),"
reportAndScreenLine "===               and audit daemon start/stop/reconfigure"
reportAndScreenLine "=== JSIG:         AU-2.a.10 System reboot, restart and shutdown (Success/Failure)" 
AUSEARCH $auditDateOptions -m SYSTEM_BOOT -m SYSTEM_SHUTDOWN -m SYSTEM_RUNLEVEL \
		-m DAEMON_START -m DAEMON_END -m DAEMON_CONFIG --format text | \
		reportLine || failAndExit
reportLine          "=== AUDIT REPORT: System start/shutdown "
reportLine          "" 

printSubsystemInstalled="no"
if [ -n "$(which lpq 2>/dev/null)" -o -n "$(which lpstat)" ]; then
   printSubsystemInstalled="yes"
fi
reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Print to a device or file:"
reportAndScreenLine "=== Description:  If printing is installed on this system,"
reportAndScreenLine "===               show something, but that code has not"
reportAndScreenLine "===               been writte yet.  See this page for ideas:"
reportAndScreenLine "===               https://www.cups.org/doc/accounting.html"
reportAndScreenLine "=== JSIG:         AU-2.a.11 Print to a device (Success/Failure)" 
reportAndScreenLine "=== JSIG:         AU-2.a.12 Print to a file (Success/Failure)" 
if [ "$printSubsystemInstalled" == "no" ]; then
   reportAndScreenLine "=== Note:         You're in luck.  No printers are configured."
   reportAndScreenLine "===               There is nothing to audit."
else
   reportAndScreenLine "=== WARNING: Not implemented yet"
fi

reportAndScreenLine "=================================================" 
reportAndScreenLine "=== AUDIT REPORT: Commands Run"
reportAndScreenLine "=== Description:  STIG-identified commands that should be reviewed"
reportAndScreenLine "===               Filters are applied to remove systemd activity"
reportAndScreenLine "=== JSIG:         AU-2.a.13 Application Initialization (Success/Failure)"
AUREPORT --comm $commonAuditOptions |egrep -v -e '(\(none\)|\? \?| abrt-cli | unix_chkpwd )'\
		| reportLine || failAndExit
reportLine          "=== AUDIT REPORT: Commands Run" 
reportLine          "" 

reportAndScreenLine "=== Compressing the extracted audit records"
gzip $auditArchiveFile
reportAndScreenLine "=+=+=+=+=+=+=+=+ Audit Review Complete =+=+=+=+=+=+=+=+=+="

echo "Now that the audit review is complete, feel free to force a log rotation with"
echo "   sudo service auditd rotate"
echo "Review this report with:        less $reportFileOnly" 



##### UNCLASSIFIED ##########
#sudo aureport --key --interpret|egrep -v -e '(logins yes /usr/sbin/crond|modules yes /usr/bin/kmod|(access|delete|export|logins|modules|perm_mod|privileged) yes \? |logins yes /usr/bin/login -1)' 
#sudo ausearch --interpret -a 34 |grep proctitle= |egrep -v -e '[0-9A-F][0-9A-F][0-9A-F]$'|sed -e 's/.*proctitle=/<</;s/$/>>/'
#localUsers=(sync|shutdown|halt|user1|ctodd.local|ctodd)
#sudo ausearch --key privileged --format text --interpret |grep -v "added-audit-rule" | grep -v "/usr/sbin/unix_chkpwd"
#localUsers=$(echo $( getent passwd |grep -v nologin | cut -f1 -d:)  | sed -e 's/^/(/;s/$/)/;s/ /|/g;')
#auditusers=$(sudo ausearch --format csv |awk 'NR>2 {print}' | cut -d, -f9 |sort | uniq)
