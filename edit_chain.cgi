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

#    Created  : 07.07.2001


require "./iptables-lib.pl";

&terror('echain_acl') if (! $access{'echains'});

my @config=&parse_config();


&header($text{'echain_title'}, undef, "echain", undef, undef, undef,
        "Written by<BR>Tim Niemueller<BR><A HREF=http://www.niemueller.de>Home://page</A>");

print "<BR><HR>";

print "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb WIDTH=100%>\n<TR>",
      "<TD COLSPAN=9 $tb WIDTH=100%><B>$in{'table'}: $in{'chain'}</B></TD></TR>\n";

if (&indexof($in{'chain'}, @{$builtins{$in{'table'}}}) >= 0) {
  my @policies=&get_by_type('POLICY', \@config);
  my %policies=();

  foreach my $p (@policies) {
    $policies{$p->{'values'}->[0]}{$p->{'values'}->[1]} = $p->{'values'}->[2];
  }

  my $policy = ($policies{$in{'table'}}{$in{'chain'}})
                 ? $text{"target_$policies{$in{'table'}}{$in{'chain'}}"}
                 : $text{'target_ACCEPT'};

  # It is a built-in chain for this table
  print "<TR><TD COLSPAN=9 $cb><B>$text{'echain_standpol'}: </B>$policy (",
        "<A HREF=\"change_policy.cgi?table=$in{'table'}&chain=$in{'chain'}&policy=$policy\">$text{'echain_spchange'}</A>)</TD></TR>\n\n";
}

print "<TR><TD><B>$text{'echain_source'}</B></TD>";
print "<TD><B>$text{'echain_port'}</B></TD>";
print "<TD><B>$text{'echain_dest'}</B></TD>";
print "<TD><B>$text{'echain_port'}</B></TD>";
print "<TD><B>$text{'echain_proto'}</B></TD>";
print "<TD><B>$text{'echain_inif'}</B></TD>";
print "<TD><B>$text{'echain_outif'}</B></TD>";
print "<TD><B>$text{'echain_target'}</B></TD>";
print "<TD ALIGN=right><B>$text{'echain_action'}</B></TD></TR>\n";

my @rules=&get_by_type('RULE', \@config);

my $rules=0;

for (my $i = 0; $i < scalar(@rules); $i++) {

  next if ( ($rules[$i]->{'values'}->[0] ne $in{'table'}) ||
            ($rules[$i]->{'values'}->[1] ne $in{'chain'}) );

  $rules++;

  print "<TR $cb><TD>$rules[$i]->{'values'}->[3]&nbsp;</TD>",
        "<TD $cb>$rules[$i]->{'values'}->[4]&nbsp;</TD>",
        "<TD $cb>$rules[$i]->{'values'}->[5]&nbsp;</TD>",
        "<TD $cb>$rules[$i]->{'values'}->[6]&nbsp;</TD>",
        "<TD $cb>$rules[$i]->{'values'}->[2]&nbsp;</TD>",
        "<TD $cb>$rules[$i]->{'values'}->[7]&nbsp;</TD>",
        "<TD $cb>$rules[$i]->{'values'}->[8]&nbsp;</TD>",
        "<TD $cb>$rules[$i]->{'values'}->[38]&nbsp;</TD>",
        "<TD $cb ALIGN=right>",
        "<A HREF=\"edit_rule.cgi?table=$in{'table'}&chain=$in{'chain'}&rule=$i\">",
        "<IMG SRC=\"images/action.edit.gif\" BORDER=0 ",
        "ALT=\"$text{'echain_edit'}\"></A> ",

        (uc ($rules[$i]->{'values'}->[39]) eq 'YES')
          ? "<A HREF=\"set_rule.cgi?table=$in{'table'}&chain=$in{'chain'}&rule=$i&status=NO\">".
            "<IMG SRC=\"images/action.disable.gif\" BORDER=0 ".
            "ALT=\"$text{'echain_disable'}\"></A> "
          : "<A HREF=\"set_rule.cgi?table=$in{'table'}&chain=$in{'chain'}&rule=$i&status=YES\">".
            "<IMG SRC=\"images/action.enable.gif\" BORDER=0 ".
            "ALT=\"$text{'echain_enable'}\"></A> ",

        "<A HREF=\"delete_rule.cgi?table=$in{'table'}&chain=$in{'chain'}&rule=$i\">",
        "<IMG SRC=\"images/action.delete.gif\" BORDER=0 ",
        "ALT=\"$text{'echain_delete'}\"></A> ",
        "<A HREF=\"clone_rule.cgi?table=$in{'table'}&chain=$in{'chain'}&rule=$i\">",
        "<IMG SRC=\"images/action.clone.gif\" BORDER=0 ",
        "ALT=\"$text{'echain_clone'}\"></A> ",
        "<A HREF=\"edit_rule.cgi?rule=$i&mode=insert\">",
        "<IMG SRC=\"images/action.insert.gif\" BORDER=0 ",
        "ALT=\"$text{'echain_insert'}\"></A> ",
        "<A HREF=\"move_rule.cgi?table=$in{'table'}&chain=$in{'chain'}&dir=up&rule=$i\">",
        "<IMG SRC=\"images/action.up.gif\" BORDER=0 ",
        "ALT=\"$text{'echain_up'}\"></A> ",
        "<A HREF=\"move_rule.cgi?table=$in{'table'}&chain=$in{'chain'}&dir=down&rule=$i\">",
        "<IMG SRC=\"images/action.down.gif\" BORDER=0 ",
        "ALT=\"$text{'echain_down'}\"></A>",
        "</TD></TR>\n";
}


if (! $rules) {
 print "<TR><TD COLSPAN=9 $cb>$text{'echain_norules'}</TD></TR>",
       "<TR><TD COLSPAN=9 $cb><A HREF=\"edit_rule.cgi?table=$in{'table'}&chain=$in{'chain'}&mode=append\"",
       ">$text{'echain_newrule'}</TD></TR>";
}

print "</TABLE>\n";

if (&indexof($in{'chain'}, @{$builtins{$in{'table'}}}) < 0) {
  print "<FORM ACTION=\"delete_chain.cgi\" METHOD=post>\n",
        "<INPUT TYPE=hidden NAME=\"table\" VALUE=\"$in{'table'}\">\n",
        "<INPUT TYPE=hidden NAME=\"chain\" VALUE=\"$in{'chain'}\">\n",
        "<INPUT TYPE=submit NAME=\"delete\" VALUE=\"$text{'delete'}\"></FORM>";
}

print "<BR><BR>\n";
print "<A HREF=\"edit_rule.cgi?chain=$in{'chain'}\">$text{'echain_crule'}</A>\n";
print "<HR>\n";



&footer("?mode=expert", $text{'echain_return'});



### END of edit_chain.cgi ###.
