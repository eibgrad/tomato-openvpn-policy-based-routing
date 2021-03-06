#!/bin/sh
export DEBUG= # uncomment/comment to enable/disable debug mode

#         name: tomato-ovpn-split-basic.sh
#      version: 0.1.14 (beta), 27-feb-2018, by eibgrad
#      purpose: redirect specific traffic over the WAN|VPN
#  script type: openvpn (route-up, route-pre-down)
# instructions:
#   1. add/modify rules to/in script for rerouting purposes; alternatively,
#      rules may be imported from filesystem using extension .rule:
#        /jffs/myrules.rule
#        /jffs/myrules2.rule
#   2. copy modified script to /jffs (or external storage, e.g., usb)
#   3. make script executable:
#        chmod +x /jffs/tomato-ovpn-split-basic.sh
#   4. create symbolic links:
#        ln -sf /jffs/tomato-ovpn-split-basic.sh /jffs/route-up
#        ln -sf /jffs/tomato-ovpn-split-basic.sh /jffs/route-pre-down
#   5. add the following to openvpn client custom configuration:
#        script-security 2
#        route-up /jffs/route-up
#        route-pre-down /jffs/route-pre-down
#   6. optional: to set/lockdown the default gateway to WAN/ISP and use
#      rules to reroute to VPN, add the following to openvpn client custom
#      configuration:
#        route-noexec
#   7. disable policy based routing (vpn tunneling->openvpn client->
#      routing policy tab)
#   8. enable syslog (status->logs->logging configuration->syslog)
#   9. (re)start openvpn client
#  limitations:
#    - due to a known bug ( http://bit.ly/2nXMSjx ), this script *might*
#      NOT be compatible w/ all versions of tomato
#    - this script is NOT compatible w/ the routing policy tab of the
#      openvpn client gui
#    - rules are limited to source ip/network/interface and destination
#      ip/network; split tunneling within any given source or destination
#      (protocol, port, etc.) is NOT supported
#    - rules do NOT support domain names (e.g., google.com)

(
[ ${DEBUG+x} ] && set -x

add_rules() {

# ----------------------------------- FYI ------------------------------------ #
# * the order of rules doesn't matter (there is no order of precedence)
# * if any rule matches, those packets bypass the current default gateway
# ---------------------------------------------------------------------------- #

# ------------------------------- BEGIN RULES -------------------------------- #

# specify source ip(s)/network(s)/interface(s) to be rerouted
add_rule iif br1 # guest network
add_rule from 192.168.1.7 # mary's pc
#add_rule from 192.168.1.14
add_rule from 192.168.2.0/24 # iot network

# specify destination ip(s)/network(s) to be rerouted
add_rule to 4.79.142.0/24 # grc.com
add_rule to 172.217.6.142 # maps.google.com

# specify source + destination to be rerouted
add_rule iif br2 to 121.121.121.121
add_rule from 192.168.1.14 to 104.25.112.26 # ipchicken.com
add_rule from 192.168.1.14 to 104.25.113.26 # ipchicken.com
#add_rule from 192.168.1.113 to 45.79.3.202 # infobyip.com
add_rule from 192.168.1.10 to 122.122.122.122
add_rule from 192.168.2.0/24 to 133.133.133.0/24

# -------------------------------- END RULES --------------------------------- #
:;}
# ------------------------------ BEGIN OPTIONS ------------------------------- #

# include user-defined rules
INCLUDE_USER_DEFINED_RULES= # uncomment/comment to enable/disable

# route openvpn dns server(s) through tunnel
ROUTE_DNS_THRU_VPN= # uncomment/comment to enable/disable

# ------------------------------- END OPTIONS -------------------------------- #

# ---------------------- DO NOT CHANGE BELOW THIS LINE ----------------------- #

WORK_DIR="tomato_ovpn_split_basic"
mkdir -p $WORK_DIR

IMPORT_DIR="$(dirname $0)"
IMPORT_RULE_FILESPEC="$IMPORT_DIR/*.rule"

CID="${dev:4:1}"
OVPN_CONF="/tmp/etc/openvpn/client${CID}/config.ovpn"

ENV_VARS="$WORK_DIR/env_vars_${CID}"
ADDED_ROUTES="$WORK_DIR/added_routes_${CID}"

# initialize work files
if [ "$script_type" == "route-up" ]; then
    # make environment variables persistent across openvpn events
    env > $ENV_VARS

    > $ADDED_ROUTES
fi

env_get() { echo $(grep -Em1 "^$1=" $ENV_VARS | cut -d = -f2); }

TID="20${CID}" # valid values: 0-25
WAN_GW="$(env_get route_net_gateway)"
VPN_GW="$(env_get route_vpn_gateway)"

add_rule() {
    ip rule del table $TID "$@" 2> /dev/null
    ip rule add table $TID "$@"
}

up() {
    [ ${DEBUG+x} ] && cat $ENV_VARS

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

    # start split tunnel
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
}

down() {
    # stop split tunnel
    while ip rule del from 0/0 to 0/0 table $TID 2> /dev/null
        do :; done

    # remove added routes
    while read route; do $route; done < $ADDED_ROUTES

    # delete alternate routing table
    ip route flush table $TID

    # force routing system to recognize changes
    ip route flush cache

    # cleanup
    rm -f $ENV_VARS $ADDED_ROUTES
}

main() {
    # reject cli invocation; script only applicable to routed (tun) tunnels
    [[ -t 0 || "$(env_get dev_type)" != "tun" ]] && return 1

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
