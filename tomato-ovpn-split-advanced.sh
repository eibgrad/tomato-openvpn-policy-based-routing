#!/bin/sh
export DEBUG= # uncomment/comment to enable/disable debug mode

#         name: tomato-ovpn-split-advanced.sh
#      version: 0.1.8 (beta), 27-feb-2018, by eibgrad
#      purpose: redirect specific traffic over the WAN|VPN
#  script type: openvpn (route-up, route-pre-down)
# instructions:
#   1. add/modify rules to/in script for rerouting purposes; alternatively,
#      rules may be imported from filesystem using extension .rule:
#        /jffs/myrules.rule
#        /jffs/myrules2.rule
#   2. copy modified script to /jffs (or external storage, e.g., usb)
#   3. make script executable:
#        chmod +x /jffs/tomato-ovpn-split-advanced.sh
#   4. create symbolic links:
#        ln -sf /jffs/tomato-ovpn-split-advanced.sh /jffs/route-up
#        ln -sf /jffs/tomato-ovpn-split-advanced.sh /jffs/route-pre-down
#   5. add the following to openvpn client custom configuration:
#        script-security 2
#        route-up /jffs/route-up
#        route-pre-down /jffs/route-pre-down
#   6. optional: to set/lockdown the default gateway to WAN/ISP and use
#      rules to reroute to VPN, add the following to openvpn client custom
#      configuration:
#        route-noexec
#   7. optional: add ipset directive(s) w/ your domains to dnsmasq custom
#      configuration:
#        ipset=/ipchicken.com/netflix.com/ovpn_split
#        ipset=/google.com/cnet.com/gov/ovpn_split
#   8. optional: add import files to /jffs (w/ extension .net); these files
#      contain hosts and networks (in cidr notation), one per line, you want
#      preloaded into ipset (ovpn_split):
#        /jffs/amazon.net
#        /jffs/netflix.net
#   9. disable policy based routing (vpn tunneling->openvpn client->
#      routing policy tab)
#  10. disable qos
#  11. enable syslog (status->logs->logging configuration->syslog)
#  12. (re)start openvpn client
#  limitations:
#    - due to a known bug ( http://bit.ly/2nXMSjx ), this script *might*
#      NOT be compatible w/ all versions of tomato
#    - this script is NOT compatible w/ the routing policy tab of the openvpn
#      client gui
#    - this script is NOT compatible w/ qos
#    - only one openvpn client can be active while using this script

(
[ ${DEBUG+x} ] && set -x

add_rules() {

# ----------------------------------- FYI ------------------------------------ #
# * the order of rules doesn't matter (there is no order of precedence)
# * if any rule matches, those packets bypass the current default gateway
# * remote access is already enabled; no additional rules are necessary
# ---------------------------------------------------------------------------- #

# ------------------------------- BEGIN RULES -------------------------------- #
add_rule -s 192.168.1.10
add_rule -p tcp -s 192.168.1.112 --dport 80
add_rule -p tcp -s 192.168.1.122 --dport 3000:3100
add_rule -i br1 # guest network
add_rule -i br2 # iot network
#add_rule -d amazon.com # domain names NOT recommended; use ipset in dnsmasq
# -------------------------------- END RULES --------------------------------- #
:;}
# ------------------------------ BEGIN OPTIONS ------------------------------- #

# include user-defined rules
INCLUDE_USER_DEFINED_RULES= # uncomment/comment to enable/disable

# route openvpn dns server(s) through tunnel
ROUTE_DNS_THRU_VPN= # uncomment/comment to enable/disable

# import additional hosts/networks (into ipset hash tables)
IMPORT_HOSTS_AND_NETWORKS= # uncomment/comment to enable/disable

# ------------------------------- END OPTIONS -------------------------------- #

# ---------------------- DO NOT CHANGE BELOW THIS LINE ----------------------- #

WORK_DIR="tomato_ovpn_split_advanced"
mkdir -p $WORK_DIR

IMPORT_DIR="$(dirname $0)"
IMPORT_RULE_FILESPEC="$IMPORT_DIR/*.rule"
IMPORT_NET_FILESPEC="$IMPORT_DIR/*.net"

CID="${dev:4:1}"
OVPN_CONF="/tmp/etc/openvpn/client${CID}/config.ovpn"

ENV_VARS="$WORK_DIR/env_vars"
RPF_VARS="$WORK_DIR/rpf_vars"
ADDED_ROUTES="$WORK_DIR/added_routes"

# initialize work files
if [ "$script_type" == "route-up" ]; then
    # make environment variables persistent across openvpn events
    env > $ENV_VARS

    > $RPF_VARS
    > $ADDED_ROUTES
fi

env_get() { echo $(grep -Em1 "^$1=" $ENV_VARS | cut -d = -f2); }

TID="200" # valid values: 1-255
WAN_GW="$(env_get route_net_gateway)"
WAN_IF="$(route -n | awk '/^0.0.0.0/{wif=$NF} END {print wif}')"
VPN_GW="$(env_get route_vpn_gateway)"
VPN_IF="$(env_get dev)"

FW_CHAIN="ovpn_split"
FW_MARK=1

IPSET_HOST="ovpn_split" # must match ipset directive in dnsmasq
IPSET_NET="ovpn_split_net"

IPT_MAN="iptables -t mangle"
IPT_MARK_MATCHED="-j MARK --set-mark $FW_MARK"
IPT_MARK_NOMATCH="-j MARK --set-mark $((FW_MARK + 1))"

add_rule() {
    $IPT_MAN -D $FW_CHAIN "$@" $IPT_MARK_MATCHED 2> /dev/null
    $IPT_MAN -A $FW_CHAIN "$@" $IPT_MARK_MATCHED
}

verify_prerequisites() {
    local err_found=false

    # policy based routing must be disabled (ip rules conflict)
    if [ "$(nvram get vpn_client${CID}_route)" == "1" ]; then
        echo "fatal error: policy based routing must be disabled"
        err_found=true
    fi

    # qos must be disabled (packet marking conflict)
    if [ "$(nvram get qos_enable)" == "1" ]; then
        echo "fatal error: qos must be disabled"
        err_found=true
    fi

    # only one active openvpn client allowed (firewall conflict)
    if pidof vpnclient1 > /dev/null && pidof vpnclient2 > /dev/null; then
        echo "fatal error: only one active openvpn client allowed"
        err_found=true
    fi

    [[ $err_found == false ]] && return 0 || return 1
}

configure_ipset() {
    # verify DNSMasq supports ipset
    if ! dnsmasq -v | grep -Eq '^.*(^|[[:space:]]+)ipset([[:space:]]+|$)'; then
        echo "warning: installed version of DNSMasq does not support ipset"
        return 1
    fi

    # load ipset module
    modprobe ip_set 2> /dev/null || return 1

    # ipset sub-modules vary depending on ipset version; adjust accordingly
    if  modprobe ip_set_hash_ip  2> /dev/null; then
        # ipset protocol 6
        modprobe ip_set_hash_net
    else
        # ipset protocol 4
        modprobe ip_set_iphash
        modprobe ip_set_nethash
    fi

    # iptables "set" module varies depending on version; adjust accordingly
    modprobe ipt_set 2> /dev/null || modprobe xt_set

    # parse the iptables version # into subversions
    _subver() { awk -v v="$v" -v i="$1" 'BEGIN {split(v,a,"."); print a[i]}'; }
    local v="$(iptables --version | grep -o '[0-9\.]*')"
    local v1=$(_subver 1)
    local v2=$(_subver 2)
    local v3=$(_subver 3)

    # iptables v1.4.4 and above has deprecated --set in favor of --match-set
    if [[ $v1 -gt 1 || $v2 -gt 4 ]] || [[ $v2 -eq 4 && $v3 -ge 4 ]]; then
       MATCH_SET="--match-set"
    else
       MATCH_SET="--set"
    fi

    return 0
}

import_hosts_and_networks() {
    # import file naming format:
    #   *.net
    # example import files:
    #   /jffs/amazon.net
    #   /jffs/netflix.net
    # import file format (one per line):
    #   ip | network(cidr)
    # example import file contents:
    #   122.122.122.122
    #   212.212.212.0/24

    local MASK_COMMENT='^[[:space:]]*(#|$)'
    local MASK_HOST='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    local MASK_HOST_32='^([0-9]{1,3}\.){3}[0-9]{1,3}/32$'
    local MASK_NET='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'

    local ERR_MSG="$WORK_DIR/tmp.$$.err_msg"

    # ipset( set host|network )
    _ipset_add() {
        if ipset -A $1 $2 2> $ERR_MSG; then
            return
        elif grep -Eq 'already (added|in set)' $ERR_MSG; then
            echo "info: duplicate host|network; ignored: $2"
        else
            cat $ERR_MSG
            echo "error: cannot add host|network: $2"
        fi
    }

    # _add_hosts_and_networks( file )
    _add_hosts_and_networks() {
        local line

        while read line; do
            # skip comments and blank lines
            echo $line | grep -Eq $MASK_COMMENT && continue

            # isolate host|network (the rest is treated as comments)
            line="$(echo $line | awk '{print $1}')"

            # line may contain host/network; add to appropriate ipset hash table
            if echo $line | grep -Eq $MASK_HOST; then
                _ipset_add $IPSET_HOST $line
            elif echo $line | grep -Eq $MASK_HOST_32; then
                _ipset_add $IPSET_HOST $(echo $line | sed 's:/32::')
            elif echo $line | grep -Eq $MASK_NET; then
                _ipset_add $IPSET_NET $line
            else
                echo "error: unknown host|network: $line"
            fi

        done < $1
    }

    local files="$(echo $IMPORT_NET_FILESPEC)"

    if [ "$files" != "$IMPORT_NET_FILESPEC" ]; then
        local file

        # add hosts and networks from each host/network file to ipset
        for file in $files; do
            _add_hosts_and_networks $file
        done
    fi

    # cleanup
    rm -f $ERR_MSG
}

up() {
    [ ${DEBUG+x} ] && cat $ENV_VARS

    # add chain for user-defined rules
    $IPT_MAN -N $FW_CHAIN
    $IPT_MAN -A PREROUTING -j $FW_CHAIN

    # initialize chain for user-defined rules
    $IPT_MAN -A $FW_CHAIN -j CONNMARK --restore-mark
    $IPT_MAN -A $FW_CHAIN -m mark ! --mark 0 -j RETURN

    # add rule for remote access over WAN or VPN
    if [ "$(env_get redirect_gateway)" == "1" ]; then
        # enable all remote access over the WAN
        add_rule -i $WAN_IF
    else
        # enable all remote access over the VPN
        add_rule -i $VPN_IF
    fi

    # add user-defined rules to chain
    if [ ${INCLUDE_USER_DEFINED_RULES+x} ]; then
        local files="$(echo $IMPORT_RULE_FILESPEC)"

        if [ "$files" != "$IMPORT_RULE_FILESPEC" ]; then
            # import (source) rules from filesystem
            for file in $files; do . $file; done
        else
            # use embedded rules
            add_rules
        fi
    fi

    # create ipset hash tables
    if [ ${IPSET_SUPPORTED+x} ]; then
        ipset -N $IPSET_HOST iphash -q
        ipset -F $IPSET_HOST
        ipset -N $IPSET_NET nethash -q
        ipset -F $IPSET_NET
    fi

    # import additional hosts and networks into ipset hash tables
    if [[ ${IMPORT_HOSTS_AND_NETWORKS+x} && ${IPSET_SUPPORTED+x} ]]; then
        import_hosts_and_networks
    fi

    # add rules for ipset hash tables
    if [ ${IPSET_SUPPORTED+x} ]; then
        add_rule -m set $MATCH_SET $IPSET_HOST dst
        add_rule -m set $MATCH_SET $IPSET_NET  dst
    fi

    # finalize chain for user-defined rules
    $IPT_MAN -A $FW_CHAIN -m mark ! --mark $FW_MARK $IPT_MARK_NOMATCH
    $IPT_MAN -A $FW_CHAIN -j CONNMARK --save-mark

    # add rules (router only)
    $IPT_MAN -A OUTPUT -j CONNMARK --restore-mark
    if [ ${IPSET_SUPPORTED+x} ]; then
        $IPT_MAN -A OUTPUT -m mark --mark 0 \
            -m set $MATCH_SET $IPSET_HOST dst $IPT_MARK_MATCHED
        $IPT_MAN -A OUTPUT -m mark --mark 0 \
            -m set $MATCH_SET $IPSET_NET  dst $IPT_MARK_MATCHED
    fi

    # clear marks (not available on all builds)
    [ -e /proc/net/clear_marks ] && echo 1 > /proc/net/clear_marks

    # route-noexec directive requires client to handle routes
    if grep -Eq '^[[:space:]]*route-noexec' $OVPN_CONF; then
        local i=1

        # search for openvpn routes
        while :; do
            local network="$(env_get route_network_$i)"

            [ "$network" ] || break

            local netmask="$(env_get route_netmask_$i)"
            local gateway="$(env_get route_gateway_$i)"

            [ "$netmask" ] || netmask="255.255.255.255"

            # add host/network route
            if route add -net $network netmask $netmask gw $gateway; then
                echo "route del -net $network netmask $netmask gw $gateway" \
                    >> $ADDED_ROUTES
            fi

            i=$((i + 1))
        done
    fi

    # route openvpn dns servers through the tunnel
    if [ ${ROUTE_DNS_THRU_VPN+x} ]; then
        awk '/dhcp-option DNS/{print $3}' $ENV_VARS \
          | while read ip; do
                if ip route add $ip via $VPN_GW; then
                    echo "ip route del $ip via $VPN_GW" >> $ADDED_ROUTES
                fi
            done
    fi

    # copy main routing table to alternate (exclude all default gateways)
    ip route show | grep -Ev '^default |^0.0.0.0/1 |^128.0.0.0/1 ' \
      | while read route; do
            ip route add $route table $TID
        done

    if [ "$(env_get redirect_gateway)" == "1" ]; then
        # add WAN as default gateway to alternate routing table
        ip route add default via $WAN_GW table $TID
    else
        # add VPN as default gateway to alternate routing table
        ip route add default via $VPN_GW table $TID
    fi

    # force routing system to recognize changes
    ip route flush cache

    # disable reverse path filtering
    for rpf in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo "echo $(cat $rpf) > $rpf" >> $RPF_VARS
        echo 0 > $rpf
    done

    # start split tunnel
    ip rule add fwmark $FW_MARK table $TID
}

down() {
    # stop split tunnel
    while ip rule del fwmark $FW_MARK table $TID 2> /dev/null
        do :; done

    # enable reverse path filtering
    while read rpf; do eval $rpf; done < $RPF_VARS

    # remove added routes
    while read route; do $route; done < $ADDED_ROUTES

    # remove rules
    while $IPT_MAN -D PREROUTING -j $FW_CHAIN 2> /dev/null
        do :; done
    $IPT_MAN -F $FW_CHAIN
    $IPT_MAN -X $FW_CHAIN
    $IPT_MAN -D OUTPUT -j CONNMARK --restore-mark
    if [ ${IPSET_SUPPORTED+x} ]; then
        $IPT_MAN -D OUTPUT -m mark --mark 0 \
            -m set $MATCH_SET $IPSET_HOST dst $IPT_MARK_MATCHED
        $IPT_MAN -D OUTPUT -m mark --mark 0 \
            -m set $MATCH_SET $IPSET_NET  dst $IPT_MARK_MATCHED
    fi

    # clear marks (not available on all builds)
    [ -e /proc/net/clear_marks ] && echo 1 > /proc/net/clear_marks

    # remove ipset hash tables
    if [ ${IPSET_SUPPORTED+x} ]; then
        ipset -F $IPSET_HOST
        ipset -X $IPSET_HOST
        ipset -F $IPSET_NET
        ipset -X $IPSET_NET
    fi

    # delete alternate routing table
    ip route flush table $TID

    # force routing system to recognize changes
    ip route flush cache

    # cleanup
    rm -f $ENV_VARS $RPF_VARS $ADDED_ROUTES
}

main() {
    # reject cli invocation; script only applicable to routed (tun) tunnels
    [[ -t 0 || "$(env_get dev_type)" != "tun" ]] && return 1

    # quit if we fail to meet any prerequisites
    verify_prerequisites || { echo "exiting on fatal error(s)"; return 1; }

    # configure ipset modules and adjust iptables "set" syntax according to version
    configure_ipset && IPSET_SUPPORTED= || { echo "warning: ipset not supported"; }

    # trap event-driven callbacks by openvpn and take appropriate action(s)
    case "$script_type" in
              "route-up")   up;;
        "route-pre-down") down;;
                       *) echo "WARNING: unexpected invocation: $script_type";;
    esac

    return 0
}

main

) 2>&1 | logger -p user.$([ ${DEBUG+x} ] && echo debug || echo notice) \
    -t $(echo $(basename $0) | grep -Eo '^.{0,23}')[$$]
