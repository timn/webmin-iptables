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

&terror('cchain_err_acl') if (! $access{'cchains'});


if ($ENV{'REQUEST_METHOD'} eq "GET") {

  &header($text{'cchain_title'}, undef, "cchain", 1, 1, undef,
         "Written by<BR>Tim Niemueller".
         "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
  print "<HR><BR>\n";

print "<FORM ACTION=\"$ENV{'SCRIPT_NAME'}\" METHOD=post>\n",
      "<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=2 $cb>\n",
      " <TR $tb>\n",
      "  <TD><b>$text{'cchain_heading'}</b></TD>\n",
      " </TR>\n",
      " <TR $cb>\n",
      "  <TD>\n",
      "   <TABLE BORDER=0>\n",
      "    <TR>\n",
      "     <TD><B>$text{'cchain_table'}:</B></TD>\n",
      "     <TD>", &table_select('table', $in{'table'}), "</TD>\n",
      "     <TD>&nbsp; &nbsp; &nbsp;</TD>\n",
      "     <TD><B>$text{'cchain_name'}:</B></TD>\n",
      "     <TD><INPUT TYPE=text NAME=\"chain\" SIZE=20></TD>\n",
      "     <TD ALIGN=right><INPUT TYPE=submit VALUE=\"$text{'cchain_createbut'}\"></TD>\n",
      "    </TR>\n",
      "   </TABLE>\n",
      "  </TD>\n",
      " </TR>\n",
      "</TABLE>\n",
      "</FORM>\n",
      "<HR>\n";

&footer("", $text{'cchain_return'});


} else {
  # POST method, so it should be a creation request

  $in{'chain'} || &terror('cchain_err_nochain');
  &terror('cchain_err_invtable') if (&indexof($in{'table'}, (keys %builtins)) < 0);

  my @config = &parse_config();
  my @chains = &get_by_type('CHAIN', \@config);
  
  foreach my $c (@chains) {
    if ( ($c->{'values'}->[0] eq $in{'table'}) &&
         ($c->{'values'}->[1] eq $in{'chain'}) ) {
      &terror('cchain_err_already', $in{'chain'}, $in{'table'});
      last;
    }
  }

  $file=&read_file_lines($config{'conffile'});
  push(@$file, "CHAIN($in{'table'}, $in{'chain'})");
  &flush_file_lines;

  redirect("?mode=expert");

}

### END of create_chain.cgi ###.
