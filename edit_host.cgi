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


&terror('ehost_err_nohost') if ($in{'host'} eq "");
&terror('ehost_err_nodb') if (! -e "$module_config_directory/hosts");


$lines=&read_file_lines("$module_config_directory/hosts");
if (!$$lines[$in{'host'}]) { &error(&text('ehost_err_notfound', $in{'host'})) }
%host=&parse_host_line($$lines[$in{'host'}]);

&header($text{'ehost_title'}, undef, ehost, undef, undef, undef,
        "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A><BR><A HREF=http://www.niemueller.de>Home://page</A>");

print <<EOM;
<BR><HR><BR>

<FORM ACTION=save_host.cgi METHOD=post>
<INPUT TYPE=hidden NAME="host" VALUE="$in{'host'}">
<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=1 $cb>
 <TR $tb>
  <TD><b>$text{'ehost_header'}</b></TD>
 </TR>
 <TR $cb>
  <TD>
  <TABLE BORDER=0>
   <TR>
    <TD><B>$text{'ehost_ip'}:</B></TD>
    <TD><INPUT TYPE=text NAME="ip" SIZE=15 MAXLENGTH=15 VALUE="$host{'ip'}"> <B>/</B> <INPUT TYPE=text NAME="netmask" SIZE=15 MAXLENGTH=15 VALUE="$host{'netmask'}"></TD>
    <TD ALIGN=right ROWSPAN=2> &nbsp;<INPUT TYPE=submit VALUE=" $text{'ehost_save'} ">&nbsp; </TD>
   </TR>
   <TR>
    <TD><B>$text{'ehost_names'}:</B></TD>
    <TD><INPUT TYPE="text" NAME="names" SIZE=34 VALUE="$host{'names'}"></TD>
   </TR>
  </TABLE>
  </TD>
 </TR>
</TABLE>
</FORM>
EOM

&footer("list_hosts.cgi", $text{'ehost_return'});

### END of edit_host.cgi ###.
