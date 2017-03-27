#!/bin/sh
export DEBUG= # uncomment/comment to enable/disable debug mode

#         name: tomato-ovpn-split-advanced.sh
#      version: 0.1.4 (beta), 26-mar-2017, by eibgrad
#      purpose: redirect specific traffic over the WAN|VPN
#  script type: openvpn (route-up, route-pre-down)
# instructions:
#   1. add/modify rules for rerouting purposes
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
#   7. optional: add ipset directive w/ your domains to dnsmasq custom
#      configuration:
#        ipset=/ipchicken.com/netflix.com/ovpn_split
#   8. disable policy based routing (vpn tunneling->openvpn client->
#      routing policy tab)
#   9. disable qos
#  10. enable syslog (status->logs->logging configuration->syslog)
#  11. (re)start openvpn client
#  limitations:
#    - due to a known bug ( http://bit.ly/2nXMSjx ), this script is only
#      compatible w/ shibby tomato v136 or earlier
#    - this script is NOT compatible w/ the routing policy tab of the
#      openvpn client gui
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
#add_rule -s 192.168.1.110
add_rule -p tcp -s 192.168.1.113 -m multiport --dports 80,443,3000:3100
add_rule -m iprange --src-range 192.168.1.200-192.168.1.209
add_rule -m mac --mac-source 00:11:22:33:44:55
add_rule -i br1 # guest network
add_rule -i br2 # iot network
add_rule -d amazon.com # domain names NOT recommended; use ipset in dnsmasq
# -------------------------------- END RULES --------------------------------- #
:;}

# route openvpn dns server(s) through tunnel
ROUTE_DNS_THRU_VPN= # uncomment/comment to enable/disable

# ---------------------- DO NOT CHANGE BELOW THIS LINE ----------------------- #

# working directory
WORK_DIR="/tmp/tomato_ovpn_split_advanced"
mkdir -p $WORK_DIR

CID="${dev:4:1}"
OVPN_CONF="/tmp/etc/openvpn/client${CID}/config.ovpn"
ENV_VARS="$WORK_DIR/env_vars"

# make environment variables persistent across openvpn events
[ "$script_type" == "route-up" ] && env > $ENV_VARS

env_get() { echo $(egrep -m1 "^$1=" $ENV_VARS | cut -d = -f2); }

TID="200" # valid values: 1-255
WAN_GW="$(env_get route_net_gateway)"
WAN_IF="$(route -n | awk '/^0.0.0.0/{wif=$NF} END {print wif}')"
VPN_GW="$(env_get route_vpn_gateway)"
VPN_IF="$(env_get dev)"

FW_CHAIN="ovpn_split"
FW_IPSET="ovpn_split" # must match ipset directive in dnsmasq
FW_MARK=1

IPT_MAN="iptables -t mangle"
IPT_MARK_MATCHED="-j MARK --set-mark $FW_MARK"
IPT_MARK_NOMATCH="-j MARK --set-mark $((FW_MARK + 1))"

add_rule() { $IPT_MAN -A $FW_CHAIN "$@" $IPT_MARK_MATCHED; }

install_ipset() {
    modprobe ip_set

    if modprobe ip_set_hash_ip; then
        # iptables version >= 1.4.4
        modprobe xt_set
        MATCH_SET="--match-set"
    else
        # iptables version < 1.4.4
        modprobe ipt_set
        MATCH_SET="--set"
    fi
}

handle_openvpn_routes() {
    local op="$([ "$script_type" == "route-up" ] && echo add || echo del)"

    # route-noexec directive requires client to handle routes
    if egrep -q '^[[:space:]]*route-noexec' $OVPN_CONF; then
        local i=0

        # search for openvpn routes
        while :; do
            i=$((i + 1))
            local network="$(env_get route_network_$i)"

            [ $network ] || break

            local netmask="$(env_get route_netmask_$i)"
            local gateway="$(env_get route_gateway_$i)"

            [ $netmask ] || netmask="255.255.255.255"

            # add/delete host/network route
            route $op -net $network netmask $netmask gw $gateway
        done
    fi

    # route openvpn dns servers through the tunnel
    if [ ${ROUTE_DNS_THRU_VPN+x} ]; then
        awk '/dhcp-option DNS/{print $3}' $ENV_VARS \
          | while read ip; do
                ip route $op $ip via $VPN_GW
            done
    fi
}

up() {
    [ ${DEBUG+x} ] && cat $ENV_VARS

    # special handler for openvpn routes
    handle_openvpn_routes

    # copy main routing table to alternate (exclude all default gateways)
    ip route show | egrep -v '^default |^0.0.0.0/1 |^128.0.0.0/1 ' \
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

    # add ipset hash table
    ipset -N $FW_IPSET iphash -q
    ipset -F $FW_IPSET

    # add chain for user-defined rules
    $IPT_MAN -N $FW_CHAIN
    $IPT_MAN -A PREROUTING -j $FW_CHAIN

    # initialize chain for user-defined rules
    $IPT_MAN -A $FW_CHAIN -j CONNMARK --restore-mark
    $IPT_MAN -A $FW_CHAIN -m mark ! --mark 0 -j ACCEPT

    # add rule for remote access over WAN or VPN
    if [ "$(env_get redirect_gateway)" == "1" ]; then
        # enable all remote access over the WAN
        add_rule -i $WAN_IF
    else
        # enable all remote access over the VPN
        add_rule -i $VPN_IF
    fi

    # add user-defined rules to chain
    add_rules

    # add rule for ipset
    add_rule -m set $MATCH_SET $FW_IPSET dst

    # finalize chain for user-defined rules
    $IPT_MAN -A $FW_CHAIN -m mark ! --mark $FW_MARK $IPT_MARK_NOMATCH
    $IPT_MAN -A $FW_CHAIN -j CONNMARK --save-mark

    # add rules (router only)
    $IPT_MAN -A OUTPUT -j CONNMARK --restore-mark
    $IPT_MAN -A OUTPUT -m mark --mark 0 \
        -m set $MATCH_SET $FW_IPSET dst $IPT_MARK_MATCHED

    # clear marks (not available on all builds)
    [ -e /proc/net/clear_marks ] && echo 1 > /proc/net/clear_marks

    # disable reverse path filtering
    for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $i; done

    # start split tunnel
    ip rule add fwmark $FW_MARK table $TID
}

down() {
    # stop split tunnel
    while ip rule del fwmark $FW_MARK table $TID 2> /dev/null
        do :; done

    # remove rules
    while $IPT_MAN -D PREROUTING -j $FW_CHAIN 2> /dev/null
        do :; done
    $IPT_MAN -F $FW_CHAIN
    $IPT_MAN -X $FW_CHAIN
    $IPT_MAN -D OUTPUT -j CONNMARK --restore-mark
    $IPT_MAN -D OUTPUT -m mark --mark 0 \
        -m set $MATCH_SET $FW_IPSET dst $IPT_MARK_MATCHED

    # clear marks (not available on all builds)
    [ -e /proc/net/clear_marks ] && echo 1 > /proc/net/clear_marks

    # remove ipset hash table
    ipset -F $FW_IPSET
    ipset -X $FW_IPSET

    # delete alternate routing table
    ip route flush table $TID

    # special handler for openvpn routes
    handle_openvpn_routes

    # force routing system to recognize changes
    ip route flush cache

    # cleanup
    rm -f $ENV_VARS
}

main() {
    # reject cli invocation; script only applicable to routed (tun) tunnels
    [[ -t 0 || "$(env_get dev_type)" != "tun" ]] && return 1

    # install and configure ipset modules
    install_ipset

    # trap event-driven callbacks by openvpn and take appropriate action(s)
    case "$script_type" in
              "route-up")   up "$@";;
        "route-pre-down") down "$@";;
                       *) echo "WARNING: unexpected invocation: $script_type";;
    esac

    return 0
}

main "$@"

) 2>&1 | logger -t $(basename $0)[$$]
