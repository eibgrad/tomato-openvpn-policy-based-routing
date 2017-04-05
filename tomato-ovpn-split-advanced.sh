#!/bin/sh
export DEBUG= # uncomment/comment to enable/disable debug mode

#         name: tomato-ovpn-split-advanced.sh
#      version: 0.1.6 (beta), 05-apr-2017, by eibgrad
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
#   8. optional: add import files to /jffs (w/ extension .ovpn_split.net);
#      these files contain hosts and/or networks (in cidr notation), one per
#      line, you want preloaded into ipset (ovpn_split):
#        /jffs/netflix.ovpn_split.net
#        /jffs/pbr/import_files/australia.ovpn_split.net
#   9. disable policy based routing (vpn tunneling->openvpn client->
#      routing policy tab)
#  10. disable qos
#  11. enable syslog (status->logs->logging configuration->syslog)
#  12. (re)start openvpn client
#  limitations:
#    - due to a known bug ( http://bit.ly/2nXMSjx ), this script **might**
#      NOT be compatible w/ all versions of tomato; please report back to the
#      author both working and non-working hardware+firmware configurations
#      so we can create a compatibility/incompatibility database
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

# ignore all user-defined rules (internal and external)
#IGNORE_USER_DEFINED_RULES= # uncomment/comment to enable/disable

# route openvpn dns server(s) through tunnel
ROUTE_DNS_THRU_VPN= # uncomment/comment to enable/disable

# import additional hosts and networks (into ipset hash tables)
#IMPORT_HOSTS_AND_NETWORKS= # uncomment/comment to enable/disable

# ---------------------- DO NOT CHANGE BELOW THIS LINE ----------------------- #

WORK_DIR="/tmp/tomato_ovpn_split_advanced"
mkdir -p $WORK_DIR

IMPORT_DIR="$(dirname $0)"
IMPORT_RULE_EXT="rule"
IMPORT_RULE_FILESPEC="$IMPORT_DIR/*.$IMPORT_RULE_EXT"
IMPORT_NET_EXT="net"
IMPORT_NET_FILESPEC="$IMPORT_DIR/*.$IMPORT_NET_EXT"
IMPORT_NET_NAME="import_hosts_and_networks"
IMPORT_NET_PROCESS_NAME="$IMPORT_NET_NAME.sh"
IMPORT_NET_SCRIPT="$WORK_DIR/$IMPORT_NET_PROCESS_NAME"
IMPORT_NET_CRU_ID="$IMPORT_NET_NAME"
IMPORT_NET_CRU_ID_1="${IMPORT_NET_CRU_ID}_1"
IMPORT_NET_CRU_ID_2="${IMPORT_NET_CRU_ID}_2"

CID="${dev:4:1}"
OVPN_CONF="/tmp/etc/openvpn/client${CID}/config.ovpn"

ENV_VARS="$WORK_DIR/env_vars"
RPF_VARS="$WORK_DIR/rpf_vars"

# make environment variables persistent across openvpn events
[ "$script_type" == "route-up" ] && env > $ENV_VARS

env_get() { echo $(egrep -m1 "^$1=" $ENV_VARS | cut -d = -f2); }

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

create_import_net_script() {

# ------------------------- BEGIN IMPORT_NET_SCRIPT -------------------------- #
cat << "EOF" > $IMPORT_NET_SCRIPT
#!/bin/sh
DEBUG=
(
[ ${DEBUG+x} ] && set -x

# import file naming format:
#   *.net
# example import files:
#   /jffs/amazon.net
#   /jffs/netflix.net
# import file format (one per line):
#   ip | network(cidr) | url | file (/path/filename)
# example import file contents:
#   122.122.122.122
#   212.212.212.0/24
#   http://www.somewebsite.com/more_hosts_and_networks/
#   ftp://ftp.someftpsite.com/more_hosts_and_networks/
#   file:/mnt/myserver/myshare/more_hosts_and_networks
#   /jffs/more_hosts_and_networks

MAX_DEPTH=3 # per file, 0=unlimited (not recommended)

# ---------------------- DO NOT CHANGE BELOW THIS LINE ----------------------- #

MASK_COMMENT='^[[:space:]]*(#|$)'
MASK_HOST='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
MASK_HOST_32='^([0-9]{1,3}\.){3}[0-9]{1,3}/32$'
MASK_NET='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
MASK_URL='^[[:space:]]*[a-zA-Z]*:/'
MASK_FILE='^[[:space:]]*/'

CURL="curl $([ ${DEBUG+x} ] || echo -sS)"
WGET="wget $([ ${DEBUG+x} ] || echo -q) -O -"

# not all builds support curl; fallback to wget (only supports http|ftp)
GET_FILE="$(which curl > /dev/null && echo $CURL || echo $WGET)"

ERR_MSG="$WORK_DIR/tmp.$$.err_msg"

# tally additions, duplicates, warnings, and errors
total_add=0
total_dup=0
total_warn=0
total_err=0

# function ipset_add( set value )
ipset_add() { 
    if ipset -A $1 $2 2> $ERR_MSG; then
        total_add=$((total_add + 1))
    elif egrep -q 'already (added|in set)' $ERR_MSG; then
        echo "info: duplicate host|network; ignored: $2"
        total_dup=$((total_dup + 1))
    else
        echo "error: cannot add host|network: $2"
        total_err=$((total_err + 1))
        return 1
    fi

    return 0
}

# function add_hosts_and_networks( file [curr-depth] )
add_hosts_and_networks() {
    local curr_depth=$([ $2 ] && echo $2 || echo 1)
    local line

    # don't exceed recursion limits
    if [[ $MAX_DEPTH -gt 0 && $curr_depth -gt $MAX_DEPTH ]]; then
        echo "warning: recursion limit ($MAX_DEPTH) exceeded: $1"
        total_warn=$((total_warn + 1))
        return
    fi

    while read line; do
        # skip comments and blank lines
        echo $line | egrep -q $MASK_COMMENT && continue

        # isolate host|network|url|file
        line="$(echo $line | awk '{print $1}')"

        # add host/network to appropriate ipset hash table

        if echo $line | egrep -q $MASK_HOST; then
            ipset_add $IPSET_HOST $line
        elif echo $line | egrep -q $MASK_HOST_32; then
            ipset_add $IPSET_HOST $(echo $line | sed 's:/32::')
        elif echo $line | egrep -q $MASK_NET; then
            ipset_add $IPSET_NET $line

        # file may contain reference to url
        elif echo $line | egrep -q $MASK_URL; then
            local file="$WORK_DIR/tmp.$$.$curr_depth.file"

            if $GET_FILE $line > $file; then
                add_hosts_and_networks $file $((curr_depth + 1))
            else
                echo "error: url not found: $line"
                total_err=$((total_err + 1))
            fi

            rm -f $file

        # file may contain reference to file (/path/filename)
        elif echo $line | egrep -q $MASK_FILE; then
            if [ -f $line ]; then
                add_hosts_and_networks $line $((curr_depth + 1))
            else
                echo "error: file not found: $line"
                total_err=$((total_err + 1))
            fi

        # undetermined; report the error
        else
            echo "error: unknown host|network|url|file: $line"
            total_err=$((total_err + 1))
        fi

    done < $1
}

main() {
    # delete cronjobs that got us here
    cru d $IMPORT_NET_CRU_ID_1
    cru d $IMPORT_NET_CRU_ID_2

    # search import directory for network files
    local files="$(echo $IMPORT_NET_FILESPEC)"

    if [ "$files" != "$IMPORT_NET_FILESPEC" ]; then

        # add hosts and networks from each network file to ipset
        for file in $files; do
            add_hosts_and_networks $file
        done
    fi

    # statistical report
    echo "info: total additions: $total_add"
    echo "info: total duplicates: $total_dup"
    echo "info: total warnings: $total_warn"
    echo "info: total errors: $total_err"

    # cleanup
    rm -f $ERR_MSG
}

# start the import
main
) 2>&1 | logger -t $(basename $0)[$$]
EOF
sed -i \
-e "s:\$WORK_DIR:$WORK_DIR:g" \
-e "s:\$IMPORT_NET_FILESPEC:$IMPORT_NET_FILESPEC:g" \
-e "s:\$IPSET_HOST:$IPSET_HOST:g" \
-e "s:\$IPSET_NET:$IPSET_NET:g" \
-e "s:\$IMPORT_NET_CRU_ID_1:$IMPORT_NET_CRU_ID_1:g" \
-e "s:\$IMPORT_NET_CRU_ID_2:$IMPORT_NET_CRU_ID_2:g" $IMPORT_NET_SCRIPT
[ ${DEBUG+x} ] || sed -ri 's/^DEBUG=/#DEBUG=/' $IMPORT_NET_SCRIPT
chmod +x $IMPORT_NET_SCRIPT
# -------------------------- END IMPORT_NET_SCRIPT --------------------------- #

} # end of create_import_net_script

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
    if pidof vpnclient1 > /dev/null && \
       pidof vpnclient2 > /dev/null; then
        echo "fatal error: only one active openvpn client allowed"
        err_found=true
    fi

    [[ $err_found == false ]] && return 0 || return 1
}

configure_ipset() {
    modprobe ip_set

    if modprobe ip_set_hash_ip; then
        # iptables version >= 1.4.4
        modprobe ip_set_hash_net
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

    # add ipset hash tables
    ipset -N $IPSET_HOST iphash -q
    ipset -F $IPSET_HOST
    ipset -N $IPSET_NET nethash -q
    ipset -F $IPSET_NET

    # import additional hosts and networks (asynchronously)
    if [ ${IMPORT_HOSTS_AND_NETWORKS+x} ]; then

        # function _cru_add( cru-id seconds )
        _cru_add() {
            cru a $1 "$(date -d @$((epoch + $2)) +"%M %H %d %m %w") \
                $IMPORT_NET_SCRIPT"
        }

        create_import_net_script
        local epoch=$(date +%s)

        # add script to scheduler; catch next and following minutes
        _cru_add $IMPORT_NET_CRU_ID_1 60
        _cru_add $IMPORT_NET_CRU_ID_2 120
    fi

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
    if [ ! ${IGNORE_USER_DEFINED_RULES+x} ]; then
        local files="$(echo $IMPORT_RULE_FILESPEC)"

        if [ "$files" != "$IMPORT_RULE_FILESPEC" ]; then
            # import rules from filesystem
            for file in $files; do . $file; done
        else
            # add embedded rules
            add_rules
        fi
    fi

    # add rules for ipset hash tables
    add_rule -m set $MATCH_SET $IPSET_HOST dst
    add_rule -m set $MATCH_SET $IPSET_NET dst

    # finalize chain for user-defined rules
    $IPT_MAN -A $FW_CHAIN -m mark ! --mark $FW_MARK $IPT_MARK_NOMATCH
    $IPT_MAN -A $FW_CHAIN -j CONNMARK --save-mark

    # add rules (router only)
    $IPT_MAN -A OUTPUT -j CONNMARK --restore-mark
    $IPT_MAN -A OUTPUT -m mark --mark 0 \
        -m set $MATCH_SET $IPSET_HOST dst $IPT_MARK_MATCHED
    $IPT_MAN -A OUTPUT -m mark --mark 0 \
        -m set $MATCH_SET $IPSET_NET dst $IPT_MARK_MATCHED

    # clear marks (not available on all builds)
    [ -e /proc/net/clear_marks ] && echo 1 > /proc/net/clear_marks

    > $RPF_VARS

    # disable reverse path filtering
    for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo "$i=$(cat $i)" >> $RPF_VARS
        echo 0 > $i
    done

    # start split tunnel
    ip rule add fwmark $FW_MARK table $TID
}

down() {
    # stop split tunnel
    while ip rule del fwmark $FW_MARK table $TID 2> /dev/null
        do :; done

    # enable reverse path filtering
    while read i; do echo ${i#*=} > ${i%=*}; done < $RPF_VARS

    # remove rules
    while $IPT_MAN -D PREROUTING -j $FW_CHAIN 2> /dev/null
        do :; done
    $IPT_MAN -F $FW_CHAIN
    $IPT_MAN -X $FW_CHAIN
    $IPT_MAN -D OUTPUT -j CONNMARK --restore-mark
    $IPT_MAN -D OUTPUT -m mark --mark 0 \
        -m set $MATCH_SET $IPSET_HOST dst $IPT_MARK_MATCHED
    $IPT_MAN -D OUTPUT -m mark --mark 0 \
        -m set $MATCH_SET $IPSET_NET dst $IPT_MARK_MATCHED

    # clear marks (not available on all builds)
    [ -e /proc/net/clear_marks ] && echo 1 > /proc/net/clear_marks

    # cancel any pending import jobs
    if cru l | grep -q $IMPORT_NET_CRU_ID; then
        cru d $IMPORT_NET_CRU_ID_1
        cru d $IMPORT_NET_CRU_ID_2
        sleep 3
    fi

    # terminate any active/running import jobs
    while pidof $IMPORT_NET_PROCESS_NAME > /dev/null; do
        killall $IMPORT_NET_PROCESS_NAME 2> /dev/null
        sleep 2
    done

    # remove ipset hash tables
    ipset -F $IPSET_HOST
    ipset -X $IPSET_HOST
    ipset -F $IPSET_NET
    ipset -X $IPSET_NET

    # delete alternate routing table
    ip route flush table $TID

    # special handler for openvpn routes
    handle_openvpn_routes

    # force routing system to recognize changes
    ip route flush cache

    # cleanup
    rm -f $ENV_VARS $RPF_VARS $IMPORT_NET_SCRIPT
}

main() {
    # reject cli invocation; script only applicable to routed (tun) tunnels
    [[ -t 0 || "$(env_get dev_type)" != "tun" ]] && return 1

    # quit if we fail to meet any prerequisites
    if ! verify_prerequisites; then
        echo "exiting on fatal error(s); correct and reboot"
        return 1
    fi

    # configure ipset modules
    configure_ipset

    # trap event-driven callbacks by openvpn and take appropriate action(s)
    case "$script_type" in
              "route-up")   up;;
        "route-pre-down") down;;
                       *) echo "WARNING: unexpected invocation: $script_type";;
    esac

    return 0
}

main

) 2>&1 | logger -t $(basename $0)[$$]
