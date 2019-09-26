#!/bin/bash
######################################################
#### WARNING PIPING TO BASH IS STUPID: DO NOT USE THIS
######################################################
# modified from: jimangel/ubuntu-18.04-scripts/prepare-ubuntu-18.04-template.sh
# that was modified from: jcppkkk/prepare-ubuntu-template.sh
# TESTED ON UBUNTU 18.04 LTS

# SETUP & RUN
# curl -sL https://raw.githubusercontent.com/maninga/ubuntu-18.04-scripts/master/prepare-ubuntu-18.04-template.sh | sudo -E bash -

if [ $(id -u) -ne 0 ]; then
	echo Need sudo
	exit 1
fi

set -v

#update apt-cache
apt update -y
apt dist-upgrade -y

#install packages
# apt install -y open-vm-tools
apt install -y cloud-init
apt install -y qemu-guest-agent
apt install -y fail2ban

# enable ipv4 forwarding
if ! grep '^net.ipv4.ip_forward = 1' /etc/sysctl.conf; then
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
fi

# disable ipv6
if ! grep '^net.ipv6.conf.all.disable_ipv6 = 1' /etc/sysctl.conf; then
    echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf
fi
if ! grep '^net.ipv6.conf.default.disable_ipv6 = 1' /etc/sysctl.conf; then
    echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.conf
fi
if ! grep '^net.ipv6.conf.lo.disable_ipv6 = 1' /etc/sysctl.conf; then
    echo 'net.ipv6.conf.lo.disable_ipv6 = 1' >> /etc/sysctl.conf
fi

# disable ipv6 autoconf
cat << 'EOL' | tee /etc/sysctl.d/disable-IPv6-autoconf.conf
# Disable IPv6 autoconf
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_ra_defrtr = 0
net.ipv6.conf.all.accept_ra_pinfo = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.lo.autoconf = 0
net.ipv6.conf.lo.accept_ra = 0
net.ipv6.conf.lo.accept_ra_defrtr = 0
net.ipv6.conf.lo.accept_ra_pinfo = 0
EOL

#Stop services for cleanup
service rsyslog stop

# clear auth and audit logs
for f in /var/log/auth.log /var/log/faillog /var/log/fail2ban.log /var/log/audit/audit.log /var/log/wtmp /var/log/lastlog; do
    if [ -f "$f" ]; then
        truncate -s0 "$"
    fi
done

# cleanup persistent udev rules
if [ -f /etc/udev/rules.d/70-persistent-net.rules ]; then
    rm /etc/udev/rules.d/70-persistent-net.rules
fi

# cleanup /tmp directories
rm -rf /tmp/*
rm -rf /var/tmp/*

#cleanup current ssh keys
rm -f /etc/ssh/ssh_host_*

# change network config by the one provided by cloud-init (ubuntu-16.04)
if [ -d /etc/network/interfaces.d ]; then
    cat << 'EOL' | tee /etc/network/interfaces
source /etc/network/interfaces.d/*
EOL
fi

# add ssh-ddos jail to fail2ban
if [ -f /etc/fail2ban/filter.d/sshd-ddos.conf ]; then
    cat << 'EOL' | tee /etc/fail2ban/jail.d/sshd-ddos.conf
[sshd-ddos]
enabled = true
EOL
fi

#add check for ssh keys on reboot...regenerate if neccessary
cat << 'EOL' | tee /etc/rc.local
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

# dynamically create hostname (optional)
if hostname | grep localhost; then
    hostnamectl set-hostname "$(grep 127.0.1.1 /etc/hosts | awk '{ print $2 }')"
fi

test -f /etc/ssh/ssh_host_dsa_key || dpkg-reconfigure openssh-server
exit 0
EOL

# make sure the script is executable
chmod +x /etc/rc.local

#reset hostname
# prevent cloudconfig from preserving the original hostname
sed -i 's/preserve_hostname: false/preserve_hostname: true/g' /etc/cloud/cloud.cfg
hostnamectl set-hostname localhost
truncate -s0 /etc/hostname

#cleanup apt
apt autoremove -y --purge
apt clean

# disable swap (docker / swarm / kubernetes)
swapoff --all
sed -ri '/\sswap\s/s/^#?/#/' /etc/fstab

# set dhcp to use mac - this is a little bit of a hack but I need this to be placed under the active nic settings
# also look in /etc/netplan for other config files
# sed -i 's/optional: true/dhcp-identifier: mac/g' /etc/netplan/50-cloud-init.yaml

if [ -f /etc/sudoers.d/90-cloud-init-users ]; then
    WEBADMIN=$(grep ALL /etc/sudoers.d/90-cloud-init-users | awk '{ print $1 }')
    # remove cloud-init sudoers file
    rm -rf /etc/sudoers.d/90-cloud-init-users
else
    WEBADMIN=$(id -un -- "1000")
fi

userdel -f -r $WEBADMIN
groupdel $WEBADMIN

for f in /etc/group /etc/gshadow /etc/passwd /etc/shadow /etc/subgid /etc/subuid; do
    if [ -f "$f" ]; then
        cp --preserve=timestamps "$f" "$f-"
    fi
done

# cleans out all of the cloud-init cache / logs - this is mainly cleaning out networking info
cloud-init clean --logs

#cleanup shell history
truncate -s0 ~/.bash_history && history -c
history -w

#shutdown
shutdown -h now
