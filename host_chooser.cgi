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

require './iptables-lib.pl';

# Build list of hosts
$hostsfile = $config{'hostsfile'} ? $config{'hostsfile'} : "/etc/hosts";
@hosts=&get_hosts($hostsfile);

if (-e "$module_config_directory/hosts") {
 push(@hosts, &get_hosts("$module_config_directory/hosts"));
}

&header();

print <<EOM;
<SCRIPT LANGUAGE="JavaScript">
function select(f)
{
 ifield.value = f;
 top.close();
 return false;
}
</SCRIPT>
<TITLE>$text{'selhost_title'}</TITLE>
<TABLE WIDTH=100%>
EOM
 foreach $h (@hosts) {
  print "<TR>\n";
  print "<TD><a href=\"\" onClick='return select(\"$h->{'ip'}/$h->{'netmask'}\")'>$h->{'ip'}/$h->{'netmask'}</TD>",
        "<TD>$h->{'names'}</TD></TR>\n";
 }
print "</TABLE>\n";

&footer();

### END of host_chooser.cgi ###.