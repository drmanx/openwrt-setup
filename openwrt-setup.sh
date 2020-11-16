function openwrt_factoryreset()
{
    echo '#### openwrt_factoryreset IPADDRESS ####'
    OPENWRTHOSTTOSETUP=$1
    ssh -t root@$OPENWRTHOSTTOSETUP '(firstboot && reboot now)'
    #   firstboot -y && reboot now
    #   umount /overlay && jffs2reset && reboot now
    ssh-keygen -f "/home/user/.ssh/known_hosts" -R "${OPENWRTHOSTTOSETUP}"
    sleeper 90
}

function openwrt_cleansetup()
{
    echo '#### openwrt_cleansetup ##############################################'
    export OPENWRTHOSTTOSETUP='192.168.1.1'
    #openwrt_factoryreset ${OPENWRTHOSTTOSETUP}
    openwrt_newsetup
    sleeper 60
    openwrt_httpsopkg
    openwrt_dnstls
    openwrt_openvpnsetup expressvpn
    openwrt_openvpnconfig_expressvpn
    sleeper 10
    openwrt_reboot
}

function openwrt_reboot()
{
    echo '#### openwrt_reboot ####'
    ssh root@$OPENWRTHOSTTOSETUP 'reboot;exit;'
}


function openwrt_openvpnconfig_expressvpn()
{
    #-----------------------------------------------------------------------
    #echo 'VPNUID' > /tmp/expressvpn_auth.txt
    #echo 'VPNPWD' >> /tmp/expressvpn_auth.txt

    cp /tmp/expressvpn_whateverconfigyourwant.ovpn /tmp/expressvpn_temp.ovpn
    
    sed -i 's/auth-user-pass/auth-user-pass \/etc\/openvpn\/expressvpn_auth.txt/g' /tmp/expressvpn_temp.ovpn
    sed -i 's/keysize 256/#keysize 256/g' /tmp/expressvpn_temp.ovpn
    #cp /root/expressvpn_temp.ovpn /etc/openvpn/expressvpn.ovpn

    scp /tmp/expressvpn_temp.ovpn root@$OPENWRTHOSTTOSETUP:/etc/openvpn/expressvpn.ovpn
    scp /tmp/expressvpn_auth.txt root@$OPENWRTHOSTTOSETUP:/etc/openvpn/expressvpn_auth.txt
    ssh root@$OPENWRTHOSTTOSETUP /etc/init.d/openvpn restart
}

function openwrt_openvpnsetup()
{
    echo '#### openwrt_openvpnsetup OpenVPN Setup ####'

    OVPNNAMEZ=$1
    OPENWRTVPNSCRIPT="$(cat <<EOF
    #opkg update
    opkg install openvpn luci-app-openvpn luci-i18n-openvpn-en
    #-------------------------------------------------------------------
    uci add openvpn ${OVPNNAMEZ}
    uci set openvpn.${OVPNNAMEZ}=openvpn
    uci set openvpn.${OVPNNAMEZ}.config='/etc/openvpn/${OVPNNAMEZ}.ovpn'
    uci set openvpn.${OVPNNAMEZ}.enabled='1'
    uci commit
    
    # Configure firewall https://openwrt.org/docs/guide-user/services/vpn/openvpn/client
    uci rename firewall.@zone[0]='lan'
    uci rename firewall.@zone[1]='wan'
    uci rename firewall.@forwarding[0]='lan_wan'
    uci del_list firewall.wan.device='tun0'
    uci add_list firewall.wan.device='tun0'
    uci commit firewall
    /etc/init.d/firewall restart
EOF
)"
	echo "${OPENWRTVPNSCRIPT}" > /tmp/openwrt_config_script.sh
	chmod +x /tmp/openwrt_config_script.sh
	scp /tmp/openwrt_config_script.sh root@192.168.1.1:/tmp
	ssh root@$OPENWRTHOSTTOSETUP '/tmp/./openwrt_config_script.sh;'
}

function openwrt_httpsopkg()
{
    echo '#### openwrt_httpsopkg /etc/opkg/distfeeds.conf /etc/opkg/customfeeds.conf ####'

    OPENWRTOPKGSCRIPT="$(cat <<EOF
    opkg update;
    opkg install ca-bundle ca-certificates
    opkg install libustream-mbedtls20150806;  #libustream-.*[ssl|tls]
    
    sed -i 's/http:/https:/g' /etc/opkg/distfeeds.conf;
    #sed -i 's/https:/http:/g' /etc/opkg/distfeeds.conf;
EOF
)"

	echo "${OPENWRTOPKGSCRIPT}" > /tmp/openwrt_config_script.sh
	chmod +x /tmp/openwrt_config_script.sh
	scp /tmp/openwrt_config_script.sh root@$OPENWRTHOSTTOSETUP:/tmp
	ssh root@$OPENWRTHOSTTOSETUP '/tmp/./openwrt_config_script.sh;'
}

function openwrt_newsetup()
{
    echo '#### openwrt_newsetup ####'
    #export WIFIBRIDGEBSSID='XX:XX:XX:XX:XX:XX'
    #export WIFIBRIDGESSID='WIFINAME'
    #export WIFIBRIDGEKEY='WIFIPSK'

    OPENWRTCONFIGSCRIPT="$(cat <<EOF
##### lan config #####
#uci del dhcp.lan.ra
#uci del dhcp.lan.dhcpv6
    
#### wifi bridge config #####
# /etc/config/firewall
uci del firewall.cfg02dc81.network
uci set firewall.cfg02dc81.network='lan'
uci del firewall.cfg03dc81.network
uci set firewall.cfg03dc81.network='wan wan6 wwan'
# /etc/config/network
uci set network.wwan=interface
uci set network.wwan.proto='dhcp'
# /etc/config/wireless
uci del wireless.radio0.disabled
uci set wireless.wifinet1=wifi-iface
uci set wireless.wifinet1.network='wwan'
uci set wireless.wifinet1.encryption='sae'
uci set wireless.wifinet1.device='radio0'
uci set wireless.wifinet1.bssid='${WIFIBRIDGEBSSID}'
uci set wireless.wifinet1.mode='sta'
uci set wireless.default_radio0.disabled='1'
uci del wireless.wifinet1.bssid
uci set wireless.radio0.htmode='HT40'
uci set wireless.radio0.channel='auto'
uci set wireless.wifinet1.ssid='${WIFIBRIDGESSID}'
uci set wireless.wifinet1.encryption='psk2'
uci set wireless.wifinet1.key='${WIFIBRIDGEKEY}'

#### ntp setup ####
uci del system.cfg01e48a.timezone
uci del system.ntp.enabled
uci set system.cfg01e48a.log_proto='udp'
uci set system.cfg01e48a.zonename='UTC'
uci set system.cfg01e48a.conloglevel='8'
uci set system.cfg01e48a.cronloglevel='5'
uci set system.ntp.enable_server='1'
uci del system.ntp.server
uci add_list system.ntp.server='pool.ntp.org'

uci commit
EOF
)"
	echo "${OPENWRTCONFIGSCRIPT}" > /tmp/openwrt_config_script.sh
	chmod +x /tmp/openwrt_config_script.sh
	scp /tmp/openwrt_config_script.sh root@$OPENWRTHOSTTOSETUP:/tmp
	ssh root@$OPENWRTHOSTTOSETUP '/tmp/./openwrt_config_script.sh;reboot;exit;'
}

function openwrt_dnstls()
{
    echo '#### openwrt_newsetup_p2 ####'

    OPENWRTCONFIGSCRIPTP2="$(cat <<EOF
    #### TLS DNS install ####
    opkg update
    opkg remove odhcpd-ipv6only
    opkg install unbound-daemon-heavy unbound-host adblock
    opkg install luci-app-unbound
    opkg install odhcpd unbound-control ca-bundle ca-certificates
    opkg remove dnsmasq
EOF
)"
	echo "${OPENWRTCONFIGSCRIPTP2}" > /tmp/openwrt_config_script.sh
	chmod +x /tmp/openwrt_config_script.sh
	scp /tmp/openwrt_config_script.sh root@$OPENWRTHOSTTOSETUP:/tmp
	ssh root@192.168.1.1 '/tmp/./openwrt_config_script.sh;'

    OPENWRTCONFIGUNBOUNDEXT="$(cat <<EOF
forward-zone:
  name: "."
  ###### https://wiki.ipfire.org/dns/public-servers
  ### censurfridns.dk
  forward-addr: 91.239.100.100@853
  ### he.net
  #forward-addr: 74.82.42.42@853
  ### cloudflare
  #forward-addr: 1.1.1.1@853
  #forward-addr: 1.0.0.1@853
  ### Cleanbrowsing 	2a0d:2a00:1::2, 2a0d:2a00:2::2
  forward-addr: 185.228.168.9@853
  forward-addr: 185.228.169.9@853
  ### Comodo Secure DNS 
  #forward-addr: 8.26.56.26@853
  #forward-addr: 8.20.247.20@853
  ### DNSReactor
  #forward-addr: 45.55.155.25@853
  #forward-addr: 104.236.210.29@853
  ### FreeDNS
  #forward-addr: 37.235.1.174@853
  #forward-addr: 37.235.1.177@853
  ### GreenTeamDNS
  #forward-addr: 81.218.119.1@853
  #forward-addr: 09.88.198.133@853
  ### Nuernberg Internet Exchange (N-IX) 
  #forward-addr: 194.8.57.12@853
  ### OpenDNS (Hosted Blacklists)
  #forward-addr: 208.67.222.222@853
  #forward-addr: 208.67.220.220@853
  #forward-addr: 208.67.220.222@853
  #forward-addr: 208.67.222.220@853
  ### Quad 9
  forward-addr: 9.9.9.10@853
  forward-addr: 149.112.112.10@853
  ### SWITCH (Hosted Blacklists)	2001:620:0:ff::2, 2001:620:0:ff::3
  forward-addr: 130.59.31.248@853
  forward-addr: 130.59.31.251@853
  ### Yandex.DNS
  #forward-addr: 77.88.8.88@853
  #forward-addr: 77.88.8.2@853
  ### SafeDNS
  #forward-addr: 195.46.39.39@853
  #forward-addr: 195.46.39.40@853
  ### Level 3 / CentryLink / Verizon
  #forward-addr: 4.2.2.1@853
  #forward-addr: 4.2.2.2@853
  #forward-addr: 4.2.2.3@853
  #forward-addr: 4.2.2.4@853
  #forward-addr: 4.2.2.5@853
  #forward-addr: 4.2.2.6@853
  #SkyDNS
  #forward-addr: 193.58.251.251@853
  #New Nations
  #forward-addr: 5.45.96.220@853

  forward-ssl-upstream: yes
EOF
)"

    echo '#### scp /etc/unbound/unbound_ext.conf ####'
	echo "${OPENWRTCONFIGUNBOUNDEXT}" > /tmp/etc_config_unbouundext
    ssh root@$OPENWRTHOSTTOSETUP 'cp /etc/unbound/unbound_ext.conf /etc/unbound/unbound_ext.conf_orig' ; #### BACKUP CONFIG
	scp /tmp/etc_config_unbouundext root@$OPENWRTHOSTTOSETUP:/etc/unbound/unbound_ext.conf

    OPENWRTCONFIGUNBOUND="$(cat <<EOF
config unbound
  option add_local_fqdn '1'
  option add_wan_fqdn '1'
  option dhcp_link 'odhcpd'
  option dhcp4_slaac6 '1'
  option domain 'lan'
  option domain_type 'static'
  option listen_port '53'
  option rebind_protection '1'
  option unbound_control '1'
EOF
)"

    echo '#### scp /etc/config/unbound ####'
	echo "${OPENWRTCONFIGUNBOUND}" > /tmp/etc_config_unbouund
    ssh root@$OPENWRTHOSTTOSETUP 'cp /etc/config/unbound /etc/config/unbound_orig' ; #### BACKUP CONFIG
	scp /tmp/etc_config_unbouund root@$OPENWRTHOSTTOSETUP:/etc/config/unbound

    #### nano /etc/config/dhcp #############################################
    OPENWRTCONFIGDHCP="$(cat <<EOF
config dnsmasq
	option domainneeded '1'
	option boguspriv '1'
	option filterwin2k '0'
	option localise_queries '1'
	option rebind_protection '1'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'lan'
	option expandhosts '1'
	option nonegcache '0'
	option authoritative '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option resolvfile '/tmp/resolv.conf.auto'
	option nonwildcard '1'
	option localservice '1'

#config dhcp 'lan'
#	option interface 'lan'
#	option start '100'
#	option limit '150'
#	option leasetime '12h'
	
config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'
	option dhcpv6 'disabled'
	option dhcpv4 'server'
	option ra 'server'
	option ra_management '1'

config dhcp 'wan'
	option interface 'wan'
	option ignore '1'

#config odhcpd 'odhcpd'
#	option maindhcp '0'
#	option leasefile '/tmp/hosts/odhcpd'
#	option leasetrigger '/usr/sbin/odhcpd-update'
#	option loglevel '4'

config odhcpd 'odhcpd'
	option maindhcp '1'
	option leasetrigger '/usr/lib/unbound/odhcpd.sh'
	option leasefile '/tmp/dhcp.leases'
EOF
)"

    echo '#### scp /etc/config/dhcp ############################################'
	echo "${OPENWRTCONFIGDHCP}" > /tmp/etc_config_dhcp
    ssh root@$OPENWRTHOSTTOSETUP 'cp /etc/config/dhcp /etc/config/dhcp_orig' ; #### BACKUP CONFIG
	scp /tmp/etc_config_dhcp root@$OPENWRTHOSTTOSETUP:/etc/config/dhcp

    echo '#### openwrt script complete and test ################################'
    OPENWRTCONFIGSCRIPTP2_1="$(cat <<EOF
    #### TLS DNS install complete and  test ####

uci add_list network.lan.dns='127.0.0.1'
uci commit

/etc/init.d/odhcpd restart
/etc/init.d/unbound restart
ps w | grep unbound
##nslookup openwrt.org localhost
#nslookup openwrt.org 127.0.0.1

#reboot
#exit
EOF
)"

	echo "${OPENWRTCONFIGSCRIPTP2_1}" > /tmp/openwrt_config_script.sh
	chmod +x /tmp/openwrt_config_script.sh
	scp /tmp/openwrt_config_script.sh root@$OPENWRTHOSTTOSETUP:/tmp
	ssh root@$OPENWRTHOSTTOSETUP '/tmp/./openwrt_config_script.sh;'
	
	nslookup openwrt.org $OPENWRTHOSTTOSETUP
}

function sleeper()
{
	echo "#### sleeper $1 ####"
	counter=$1
	while [ $counter -ge 0 ]
	do
		echo "### $counter "
		((counter--))
		sleep 1
	done
}
