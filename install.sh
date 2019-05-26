#!/bin/sh
sudo install -t /etc/systemd/system continuous_audit_to_syslog.service 
sudo install -t /root continuous_audit_to_syslog
sudo systemctl enable continuous_audit_to_syslog 
sudo systemctl start continuous_audit_to_syslog 
sleep 1
systemctl status continuous_audit_to_syslog 
