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

if (! -e "$module_config_directory/hosts") {
 ## We have not build our host dbase, so we make it now.
 &generate_hostsfile("$module_config_directory/hosts");
}

$hostsfile = $config{'hostsfile'} ? $config{'hostsfile'} : "/etc/hosts";
@etchosts=&get_hosts($hostsfile);
@userhosts=&get_hosts("$module_config_directory/hosts");

&header($text{'lhosts_title'}, undef, undef, undef, undef, undef,
        "Written by<BR>Tim Niemueller<BR><A HREF=http://www.niemueller.de>Home://page</A>");


print <<EOM;
<BR><HR>

<TABLE BORDER=0 CELLPADDING=10 WIDTH=100%>
<TR><TD WIDTH=50% VALIGN=top>

<H3>$text{'lhosts_etc'}</H3>

<TABLE BORDER=1 WIDTH=100% CELLSPACING=0 CELLPADDING=1 $cb>
<TR>
 <TD $tb><B>$text{'lhosts_ip'}</B></TD>
 <TD $tb><B>$text{'lhosts_names'}</B></TD>
</TR>
EOM

for (my $i = 0; $i <= @etchosts - 1; $i++)
{
 print "<TR>\n";
 print "<TD>$etchosts[$i]->{'ip'}/$etchosts[$i]->{'netmask'}</TD>";
 print "<TD>$etchosts[$i]->{'names'}</TD>";
 print "</TR>";
} 


print <<EOM;
</TABLE>
</TD>
<TD WIDTH=50% VALIGN=top>
<H3>$text{'lhosts_usrdef'}</H3>

<TABLE BORDER=1 WIDTH=100% CELLSPACING=0 CELLPADDING=1 $cb>
<TR>
 <TD $tb><B>IP</B></TD>
 <TD $tb COLSPAN=2><B>$text{'lhosts_names'}</B></TD>
</TR>
EOM

for (my $i = 0; $i <= @userhosts - 1; $i++)
{
 print "<TR>\n";
 print "<TD>$userhosts[$i]->{'ip'}/$userhosts[$i]->{'netmask'}</TD>";
 print "<TD>$userhosts[$i]->{'names'}</TD>";
 print "<TD ALIGN=center><A HREF=\"edit_host.cgi?host=$userhosts[$i]->{'line'}\">",
       "<IMG SRC=images/action.edit.gif BORDER=0 ALT=\"$text{'lhosts_edit'}\"></A> ",
       "<A HREF=\"delete_host.cgi?host=$userhosts[$i]->{'line'}\">",
       "<IMG SRC=images/action.delete.gif BORDER=0 ALT=\"$text{'lhosts_delete'}\"></A></TD>";
 print "</TR>";
} 
if (!@userhosts) {
 print "<TR><TD COLSPAN=3>$text{'lhosts_nud'}</TD></TR>";
}

print <<EOM;
</TABLE>
</TD></TR></TABLE>

<BR><HR><BR>

<TABLE BORDER=0 CELLSPACING=10>
<TR>
<TD VALIGN=top>

<FORM ACTION=save_host.cgi METHOD=post>
<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=1 $cb>
 <TR $tb>
  <TD><b>$text{'lhosts_add'}</b></TD>
 </TR>
 <TR $cb>
  <TD>
  <TABLE BORDER=0>
   <TR>
    <TD><B>$text{'lhosts_ip'}:</B></TD>
    <TD><INPUT TYPE=text NAME="ip" SIZE=15 MAXLENGTH=15> <B>/</B> <INPUT TYPE=text NAME="netmask" SIZE=15 MAXLENGTH=15></TD>
    <TD ALIGN=right ROWSPAN=2> &nbsp;<INPUT TYPE=submit VALUE="$text{'lhosts_but_create'}">&nbsp; </TD>
   </TR>
   <TR>
    <TD><B>$text{'lhosts_names2'}:</B></TD>
    <TD><INPUT TYPE="text" NAME="names" SIZE=34></TD>
   </TR>
  </TABLE>
  </TD>
 </TR>
</TABLE>
</FORM>

</TD>

</TR></TABLE>

EOM

&footer("./", $text{'lhosts_return'});


### END of list_hosts.cgi ###.
