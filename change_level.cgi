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

#    Created  : 30.08.2000


require "./iptables-lib.pl";

&terror('clev_err_wrong') if ($in{'level'} !~ /^(disabled|low|medium|high|full)$/);



if ($in{'confirm'}) {
  # confirmed, change it

  my @combs=&get_iface_combs();

  my @level = &parse_level($in{'level'}, $config{'fwtype'});


  &create_basic_conf($config{'conffile'},
                     "newbie",
                     $in{'level'},
                     $config{'fwtype'},
                     ($MASQ) ? "masq" : undef,
                     1, 1
                     ) || &terror('clev_err_write');


  open(CONF, ">>$config{'conffile'}");

  foreach my $t (keys %{$level[0]}) {
    foreach my $c (keys %{$level[0]->{$t}}) {
      print CONF "POLICY($t, $c, $level[0]->{$t}->{$c})\n";
    }
  }

  close(CONF);


  &write_basics($config{'conffile'});


  if ($in{'level'} ne 'disabled') {

    # To make it easy everything is considered external
    # internal of course ot :-)
    #
    # Tokens are not filled any longer in this script, this
    # is now done by iptfw.pl on each run! That makes it a lot
    # more flexible

    open(CONF, ">>$config{'conffile'}");

    foreach my $c (@combs) {

      my @templates = &get_templates();
      my @defs = keys %{$level[1]};

      foreach my $t (@templates) {

        if (&indexof($t, @defs) >= 0) {
          # This template is used in the configuration

          my %templ = &parse_template($t);

          foreach $direction (@{$level[1]->{$t}}) {
            if (defined($templ{$short2long{$direction}})) {

              print CONF "# $c->{'left'}->{'values'}->[0] > $c->{'right'}->{'values'}->[0] : $t : $direction [\n";
              # print "# $c->{'left'}->{'values'}->[0] > $c->{'right'}->{'values'}->[0] : $t : $direction [<BR>\n";

              foreach $r (@{$templ{$short2long{$direction}}}) {

                my $tmp = &transform_token_net($r, $c->{'left'}, $c->{'right'});
                if ($in{'masq'}) {
                  if ( ($c->{'right'}->{'values'}->[1] eq 'internet') && ($tmp =~ /^MASQ-(.+)$/)) {
                    $tmp = $1;
                  }
                }
                print CONF "$tmp\n";

              }

              print CONF "# $c->{'left'}->{'values'}->[0] > $c->{'right'}->{'values'}->[0] : $t : $direction ]\n";
              # print "# $c->{'left'}->{'values'}->[0] > $c->{'right'}->{'values'}->[0] : $t : $direction ]<BR>\n";

            }
          }

        } # else { nothing }
      }

    }

    close(CONF);

  } ## END if disabled

  # Now run the script to make the changes active
  # if (!-x $config{'conffile'}) {
    # chmod 0700, $config{'conffile'};
  # }

  # Run that... firewall script ... if wanted
  # system($config{'conffile'}) if ($in{'run'});

  &redirect("");

} else {
  # not confirmed, display description

  &header($text{'clev_title'}, undef, "changelevel", undef, undef, undef,
          "Written by<BR>Tim Niemueller".
          "<BR><A HREF=http://www.niemueller.de>Home://page</A>");

  my $u = $ENV{'REMOTE_USER'};
  my $lang = $gconfig{"lang_$u"}
               ? $gconfig{"lang_$u"}
               : $gconfig{"lang"}
                 ? $gconfig{"lang"}
                 : "en";


  print "<HR><BR>\n<H3>",
        &text('clev_heading', $text{"index_$config{'fwtype'}"}),
        "</H3>\n",
        "<TABLE BORDER=0>\n",
        " <TR>\n",
        "  <TD><IMG SRC=\"images/",
        (-e "images/$in{'level'}.$lang.gif") ? "$in{'level'}.$lang.gif" : "$_.gif",
        "\" BORDER=0></TD>\n",
        "  <TD>&nbsp; &nbsp; &nbsp;</TD>\n",
        "  <TD>", $text{"clev_desc_$in{'level'}"}, "</TD>\n",
        " </TR>\n",
        "</TABLE>\n",
        
        "<BR><BR><BR>";

  # Now always false, will check on that in next version
  if (scalar(@templates)) {
    print "<TABLE BORDER=0>\n<TR>",
          "<TD><B>$text{'clev_prot'}</B></TD><TD>&nbsp;</TD>",
          "<TD><B>$text{'clev_dirs'}</B></TD></TR>\n",
          "<TR><TD COLSPAN=3><HR></TD></TR>\n";

    foreach $t (@templates) {
      ($name, @dirs) = split(/-/, $t);
      $name =~ s/\./-/g;
      for (my $i=0; $i < @dirs; $i++) {
        chomp $dirs[$i];
        $dirs[$i] = $text{"index_$dirs[$i]"};
      }
      print "<TR><TD><B>$name</B></TD><TD>&nbsp;</TD><TD>",
            join(', ', @dirs),
            "</TD></TR>\n";
    }

    print "</TABLE>\n";

  } else {
    if ($in{'level'} eq 'full') {
      print "<TR><TD COLSPAN=3><B>$text{'clev_nocons'}</B></TD></TR>\n";
    }
  }

  print "<BR><BR><BR><FORM ACTION=\"$ENV{'SCRIPT_NAME'}\" METHOD=post>",
        ($config{'fwtype'} eq 'router') ?
           $text{"clev_$in{'level'}_masq"}."<BR>" : "",
        "<INPUT TYPE=checkbox NAME=run VALUE=1> $text{'clev_enable'}\n",
        "<BR><BR><BR>",
        "<INPUT TYPE=hidden NAME=level VALUE=$in{'level'}>",
        "<INPUT TYPE=submit NAME=confirm VALUE=\"$text{'clev_change'}\">",
        "</FORM><BR><HR>\n";

  &footer("", $text{'clev_return'});

}


### END of change_level.cgi ###.
