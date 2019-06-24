# Linux Audit Reporting, version 1.0

## Executive Summary

Automate a manual audit review of a system to ensure that complete
coverage is obtained for CNSS 1253 or JSIG, both of which are based
upon NIST SP 800-53r4.

## Background

National security systems have stringent auditing requirements
that monitor users.  Detailed audit records allow for complete
and thorough forensic investigations of an incident.  Audit 
records may even be considered as evidence, in the legal sense,
should a prosecution be required.  Auditors must also be able
to prove that they are routinely performing audit reviews.

Auditing a Linux operating system has several pieces.  Configuring
the audit subsystem, verifying that all audit requirements are
covered, collecting the audits during daily usage, reviewing the
audit records, archiving the audit records and any reports.  This 
program primarily focuses on review and archiving of audit records.

This program is archived at https://gitlab.ext.rdte.afrl.af.mil/toddch/linux-audit-reporting [CAC required].

## Quick Usage

### Prerequisites

- Version 1.0 only supports Red Hat Enterprise Linux 7.  Open an issue if other platforms are needed.  
- The system must already be compliant with a baseline that configured the AU-2 requirements for CNSS or JSIG (e.g. DISA STIG)
- The user running the script must have sudo access
- The script insists on recording who is running the report, so logging in as root, as security violation, is recorded

### Basics

1. Either check out the code from the Git repository or download the
   ZIP, copy it to the system, and extract it to the auditor's home directory
1. Log in as an auditor who has sudo access
1. Change the working directory to the folder with this script with `cd linux_audit_reporting`
1. Start a review the last 30 days of audit records with `./linux_audit_reporting`
1. Read the detailed report as listed at the end of the script. (e.g. `more archive/20190624_034601-syslog1-audit_report.txt`)
1. Copy the report and audit log excerpt to removable media.  Example methods:
   - Secure copy (`scp`) to another Unix/Linux host
   - Secure copy from another system (e.g. WinSCP on Windows)

## Sample Run

### Start up
```bash
[auditor@syslog1 ~]$ cd linux_audit_reporting
[auditor@syslog1 linux_audit_reportsing]$ ./linux_audit_reporting
```
```
=================================================
Audit review of:     syslog1.example.com on Mon Jun 24 03:46:01 EDT 2019
Review conducted by: auditor
This report:         20190624_034601-syslog1-audit_report.txt
Earliest audit date: 05/25/2019 03:46:01 (30 days ago)
Latest audit date:   06/24/2019 03:46:01
Archive audit file:  ./archive/syslog1.example.com-audit_archive-20190525_034602_to_20190624_034602.log
This program:        /home/auditor/linux_audit_reporting/linux_audit_report
This program checksum:     f6c691d26f06a79e429ace79440f0c81982bb64062afc592f710bfe3f452472a  - (SHA256)
This program lastmodified: 2019-06-24 03:45:56.914291214 -0400
=================================================
```

### Sanity Checks and Review Prep
The details of each run are saved to the report file.  What is shown
is just a quick way to keep track of the current activity in generating
the report.  Since audit records may be long, this allows the auditor
to fire off the report and come back.
```
=================================================
=== Quick audit configuration check
    ERROR: There were 13 unparsed audit rules in /etc/audit/rules.d
           so auditing may be incomplete.
    A quick check to see that all rules are being implemented found 1 problems.
    Audit rules exist to monitor access to security-relevant logs
=== Quick audit configuration check complete
```
*NOTE* The previous check is looking for consistency in the audit records
so if it detects that some audit records are not being watched, then
the auditor is alerted.  The review will continue, but the official
record is that the auditor was warned that their review was incomplete.

```
=================================================
=== Archiving the audit records for integrity and to
===    only record one access while writing this report
=== Archiving complete
```
In order to minimize audit record noise, the audit records are pulled
once at the beginning of each review run.  This should make any
reads by a non-auditor much more obvious.

### Basic Reports
A few overview reports are run which set context and 
leverage the existing anlysis tools that come with Linux.
```
=================================================
=== AUDIT REPORT: Summary
=== Description:  A brief overview of events
=== AUDIT REPORT: Summary

=================================================
=== AUDIT REPORT: Anomaly Events
=== Description:  Strange events that should rarely occur
=== AUDIT REPORT: Anomaly Events

### CNSS/JSIG Specific Audit Reviews
A full report is then run which goes through the requirements
one by one so that the auditor can be assured that they
are reviewing all required rules.

Sometimes, an error will be detected.  The auditor will
be alerted about problem areas.  One example is below.
```
=================================================
=== AUDIT REPORT: Digital Media (mount/unmount)
=== Description:  All events for portable media, be it
===               mount, unmount, read, or write
=== Note:         This audit requirement is difficult to
===               satisfy under Linux with the native audit
===               system.  If user-mountable drives are
===               configured, your administrator should have
===               auditd configured to watch those paths and
===               this script modified to support it.
=== CNSS/JSIG:    AU-2.a.3 Export/Write to digital media [partial]
=== CNSS/JSIG:    AU-2.a.4 Import from digital media [partial]
    Note:             this system has tools to build ISOs, so
                      files could be exfiltrated this way as a bundle.
    WARNING: /usr/bin/cdrecord is not being watched by the audit daemon
    WARNING: /usr/bin/devdump is not being watched by the audit daemon
    WARNING: /usr/bin/dvdrecord is not being watched by the audit daemon
    WARNING: /usr/bin/readom is not being watched by the audit daemon
    WARNING: /usr/bin/wodim is not being watched by the audit daemon
    WARNING: Optical media or image generation tools are not fully audited.
    Suggestion:       create a watch on optical media tools
                      by copying 02-media.rules to /etc/audit.d/rules.d
                         sudo mv 02-media.rules /etc/audit/rules.d && \
                         sudo service auditd restart
```
A system-specific file will be created help the auditor with a one-time
fix to the system that provides better coverage of the requirement.

## RMF Requirements Satisfied
Surprise!  This script does *not* satisfy AU-2, which is just a requirement
to collect the audit.  If the system had no auditing configuration, this
script would not be effective.

In the list of NIST SP 800-53r4 requirements below, this script either
directly implements the requirement, or empowers the user to satisfy
the requirement with a few additional procedures.  An example of 
"additional procecures" might be steps to mount a USB storage device to
the system and then to use the `-a` command line option to automatically
archive the audit log and generated report.

* AC-5 - Separation of Duties
* AU-6 - Audit Review, Analysis, and Reporting
   * AU-6(8) - Full Text Analysis of Privileged Commands
* AU-7 - Audit Reduction and Report Generation
   * AU-7(1) - Automatic Processiing
   * AU-7(2) - Automatic Sort and Search
* AU-9 - Protection of Audit Information
   * AU-9(2) - Audit Backup on Separate Physical Systems
* AU-11 - Audit Record Retention
* AU-12(2) - Audit Generation - Standardized Formats
* CM-3.d - Configuration Change Control - audit configuration changes
* AC-6(9) - Least Privilege - auditing use of privileged functions

### SUDO Considerations
Some sites may choose to not grant an auditor broad access to the system
via sudo.  All sudo access inside the `linux_audit_reporting` script is one of these command lines:
* `auditctl -l`
* `cat /etc/audit/auditd.conf`
* The quickAuditCheck function would need to be optimized to extract the
  the rules.d files to a temporary location where permission is less onerous,
  perform the analysis, and then delete the temporary location
* `/usr/sbin/ausearch` _multiple parameters_
* `/usr/sbin/aureport` _multiple parameters_
* List the sudo privileges (used to verify sudo access)

No effort has been made to provide a very restricted sudo configuration
as would be needed to satisfy AC-6, "Least Privilege".
