#
#    IPchains Firewalling Webmin Module Library
#    Copyright (C) 1999-2000 by Tim Niemueller <tim@niemueller.de>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    Created  : 12.07.2000


## /* Values for "fw_flg" field .  */
$IP_FW_F_PRN=0x0001;     # /* Print packet if it matches */
$IP_FW_F_TCPSYN=0x0002;  # /* For tcp packets-check SYN only */
$IP_FW_F_FRAG=0x0004;    # /* Set if rule is a fragment rule */
$IP_FW_F_MARKABS=0x0008; # /* Set the mark to fw_mark, not add. */
$IP_FW_F_WILDIF=0x0010;  # /* Need only match start of interface name. */
$IP_FW_F_NETLINK=0x0020; # /* Redirect to netlink: 2.1.x only */
$IP_FW_F_MASK=0x003F;    # /* All possible flag bits mask   */

## /* Values for "fw_invflg" field. */
$IP_FW_INV_SRCIP=0x0001; # /* Invert the sense of fw_src. */
$IP_FW_INV_DSTIP=0x0002; # /* Invert the sense of fw_dst. */
$IP_FW_INV_PROTO=0x0004; # /* Invert the sense of fw_proto. */
$IP_FW_INV_SRCPT=0x0008; # /* Invert the sense of source ports. */
$IP_FW_INV_DSTPT=0x0010; # /* Invert the sense of destination ports. */
$IP_FW_INV_VIA=0x0020;   # /* Invert the sense of fw_vianame. */
$IP_FW_INV_SYN=0x0040;   # /* Invert the sense of IP_FW_F_TCPSYN. */
$IP_FW_INV_FRAG=0x0080;  # /* Invert the sense of IP_FW_F_FRAG. */

%icmptypes= ( "echo-reply" => ["0", "0:65535"],
              "destination-unreachable" => ["3", "0:65535"],
              "network-unreachable" => ["3", "0"],
              "host-unreachable" => ["3", "1"],
              "protocol-unreachable" => ["3", "2"],
              "port-unreachable" => ["3", "3"],
              "fragmentation-needed" => ["3", "4"],
              "source-route-failed" => ["3", "5"],
              "network-unknown" => ["3", "6"],
              "host-unknown" => ["3", "7"],
              "network-prohibited" => ["3", "9"],
              "host-prohibited" => ["3", "10"],
              "TOS-network-unreachable" => ["3", "11"],
              "TOS-host-unreachable" => ["3", "12"],
              "communication-prohibited" => ["3", "13"],
              "host-precedence-violation" => ["3", "14"],
              "precedence-cutoff" => ["3", "15"],
              "source-quench" => ["4", "0:65535"],
              "redirect" => ["5", "0:65535"],
              "network-redirect" => ["5", "0"],
              "host-redirect" => ["5", "1"],
              "TOS-network-redirect" => ["5", "2"],
              "TOS-host-redirect" => ["5", "3"],
              "echo-request" => ["8", "0:65535"],
              "router-advertisement" => ["9", "0:65535"],
              "router-colicitation" => ["10", "0:65535"],
              "time-exceeded" => ["11", "0:65535"],
              "ttl-zero-during-transit" => ["11", "0"],
              "ttl-zero-during-reassembly" => ["11", "1"],
              "parameter-problem" => ["12", "0:65535"],
              "ip-header-bad" => ["12", "0"],
              "required-option-missing" => ["12", "1"],
              "timestamp-request" => ["13", "0:65535"],
              "timestamp-reply" => ["14", "0:65535"],
              "address-mask-request" => ["17", "0:65535"],
              "address-mask-reply" => ["18", "0:65535"]
             );


sub denumberize {
 my $tmpstr=join('.', ($_[0] & 0xff000000) >> 24,
                     ($_[0] & 0x00ff0000) >> 16,
                     ($_[0] & 0x0000ff00) >> 8,
                     ($_[0] & 0x000000ff) );
$tmpstr;
}



1;
### END of import-lib.cgi ###.