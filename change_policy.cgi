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

#    Created  : 21.07.2001


require "./iptables-lib.pl";

@config=&parse_config();
my $policy;

if ( &indexof($in{'chain'}, @{$builtins{$in{'table'}}}) >= 0 )  {

  my @policies=&get_by_type('POLICY', \@config);
  my %policies=();

  foreach my $p (@policies) {
    $policies{$p->{'values'}->[0]}{$p->{'values'}->[1]} = $p->{'values'}->[2];
  }

  my $policytext = ($policies{$in{'table'}}{$in{'chain'}})
                     ? $text{"target_$policies{$in{'table'}}{$in{'chain'}}"}
                     : $text{'target_ACCEPT'};
 $policy = ($policies{$in{'table'}}{$in{'chain'}})
                 ? $policies{$in{'table'}}{$in{'chain'}}
                 : 'ACCEPT';

} else {
 &terror('cpol_err_builtin');
}


&header($text{'cpol_title'}, undef, "changepol", undef, undef, undef,
        "Written by<BR>Tim Niemueller<BR><A HREF=http://www.niemueller.de>Home://page</A>");

print "<BR><HR>";


print "<FORM ACTION=\"save_policy.cgi\" METHOD=post>\n",
      "<INPUT TYPE=hidden NAME=\"table\" VALUE=\"$in{'table'}\">\n",
      "<INPUT TYPE=hidden NAME=\"chain\" VALUE=\"$in{'chain'}\">\n",
      "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb>\n",
      " <TR>\n",
      "  <TD COLSPAN=2 $tb WIDTH=100%><B>",
      &text('cpol_pol', $in{'chain'}, $in{'table'}),
      "</B></TD>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD $cb ALIGN=center><SELECT NAME=\"policy\">\n";

for $p (sort @standardpolicies) {
 print " <OPTION VALUE=\"$p\"",
       ($policy eq $p) ? " selected" : "",
       ">",
       $text{"target_$p"},
       "\n";
}

print "  </SELECT>\n",
      "  </TD>\n",
      "  <TD ALIGN=center><INPUT TYPE=submit VALUE=\" $text{'save'} \"></TD>\n",
      " </TR>\n",
      "</TABLE>\n",
      "</FORM>\n",
      "<BR><BR>\n";

&footer("edit_chain.cgi?table=$in{'table'}&chain=$in{'chain'}", &text('cpol_return', $in{'chain'}, $in{'table'}));

### END of change_policy.cgi ###.
