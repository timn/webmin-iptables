#!/usr/bin/perl
#
#    IPtables Firewall Webmin Module
#    Copyright (C) 2001 by Tim Niemueller <tim@niemueller.de>
#    Website: http://www.niemueller.de/webmin/modules/iptables/
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

#    Created  : 23.07.2001

require "./iptables-lib.pl";

# Nearly unchanged from ipchains module
# OK, the code IS ugly, but I don't care, it works ;-)
# OK, I DO care, but I'm now just to lazy to make it nice...


if ($in{'host'}) {
 if (! $access{'ehosts'}) { &error($text{'shost_err_acl'}) }
} else {
 if (! $access{'chosts'}) { &error($text{'shost_err_acl2'}) }
}

if ((!$in{'ip'}) && (!&check_ipaddress($in{'ip'}))) { &error($text{'shost_err_invip'}) }
if ((!$in{'netmask'}) && ( (!&check_ipaddress($in{'netmask'})) || ($in{'netmask'} !~ /^\d+$/) )) { &error($text{'shost_err_invnetmask'}) }
if (!$in{'names'}) { &error($text{'shost_err_invname'}) }

if (! -e "$module_config_directory/hosts") {
## We have not build our host dbase, so we make it now.
 &generate_hostsfile("$module_config_directory/hosts");
}

$lines=&read_file_lines("$module_config_directory/hosts");
$newline="$in{'ip'}/$in{'netmask'} $in{'names'}";
if ($in{'host'}) {
 # we are changing an existing host.
 if (!$$lines[$in{'host'}]) { &error($text{'shost_err_nohost'}) }
 $$lines[$in{'host'}] = $newline;
} else {
 # we are creating a new host
 push(@{$lines}, $newline);
}
&flush_file_lines;

redirect("list_hosts.cgi");

### END of save_host.cgi ###.