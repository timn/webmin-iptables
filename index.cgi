#!/usr/bin/perl
#
#    IPtables Firewalling Webmin Module
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

#    Created  : 23.06.2001

#    Changes and To Do are in the file CHANGES

require "./iptables-lib.pl";
my @config=&parse_config();
my @defif=&get_by_type('INTERFACE', \@config);
my @valif=&get_interfaces() if (&foreign_check('net') || $config{'netifaces'});

if (! $config{'conffile'}) {
    # config file location is not set in the config, ask for it

    &header($text{'index_title'}, undef, "index_sf", 1, 1, undef,
            "Written by<BR>Tim Niemueller".
            "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
    print "<HR><BR>\n",
          "<H3>$text{'index_cfnotdef'}</H3>\n",
          $text{'index_desc_cfdef'},
          "<FORM ACTION=\"save_config.cgi\" METHOD=post>",
          $text{'index_conffile'},
          ": <INPUT TYPE=text NAME=conffile VALUE=\"/etc/iptfw.conf\" SIZE=30>",
          "<BR><INPUT TYPE=submit NAME=save VALUE=\"$text{'save'}\"></FORM>";

    print "<HR>\n";
    &footer("/", $text{'index_return'});


} elsif (! -e $config{'conffile'}) {

  &create_basic_conf($config{'conffile'});

  # Now make it safe (owned by root, permissions 600)
  chown 0, 0, $config{'conffile'};
  chmod 0600, $config{'conffile'};

  &redirect();

} elsif ((! &foreign_check('net')) && (! $config{'netifaces'}) ) {
  # Cannot automatically detect network interfaces

    &header($text{'index_title'}, undef, "index_sf", 1, 1, undef,
            "Written by<BR>Tim Niemueller".
            "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
    print "<HR><BR>\n",
          "<H3>$text{'index_ifnotdef'}</H3>\n",
          $text{'index_desc_ifdef'},
          "<FORM ACTION=\"save_config.cgi\" METHOD=post>",
          $text{'index_interfaces'},
          ": <INPUT TYPE=text NAME=netifaces VALUE=\"\" SIZE=50>",
          "<BR><INPUT TYPE=submit NAME=save VALUE=\"$text{'save'}\"></FORM>";

    print "<HR>\n";
    &footer("/", $text{'index_return'});

} elsif (scalar(@defif) != scalar(@valif)) {
    # internal and external interface not yet defined, do that!

    &header($text{'index_title'}, undef, "index_ifaces", 1, 1, undef,
           "Written by<BR>Tim Niemueller".
           "<BR><A HREF=http://www.niemueller.de>Home://page</A>");

    print "<HR><BR>\n",
          "<H3>$text{'index_devnotdef'}</H3>\n",
          $text{'index_desc_devdef'}, "<BR><BR>\n",
          $text{'index_desc_internal'}, "<BR>\n",
          $text{'index_desc_external'}, "<BR>\n",
          $text{'index_desc_dmz'}, "<BR>\n",
          $text{'index_desc_internet'}, "<BR>\n",
          $text{'index_desc_ignore'}, "<BR>\n",
          "<FORM ACTION=\"save_interfaces.cgi\" METHOD=post>",
          "<TABLE BORDER=0>\n";

    foreach my $if (@valif) {
      print "<TR><TD><B>$if</B></TD><TD>",
            &type_select($if),
            "</TD></TR>\n";
    }

    print "<TR><TD>&nbsp;</TD><TD>",
          "<INPUT TYPE=submit NAME=save VALUE=\"$text{'save'}\">",
          "</TD></TR></TABLE></FORM>";

    print "<HR>\n";
    &footer("/", $text{'index_return'});

}elsif (! $bootdir) {
  # Could not find init dir (tried the init module), ask for it

    &header($text{'index_title'}, undef, "index_boot", 1, 1, undef,
            "Written by<BR>Tim Niemueller".
            "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
    print "<HR><BR>\n",
          "<H3>$text{'index_bootnotdef'}</H3>\n",
          $text{'index_desc_bootdef'},
          "<FORM ACTION=\"save_config.cgi\" METHOD=post>",
          $text{'index_dir'},
          ": <INPUT TYPE=text NAME=bootloc>",
          &file_chooser_button('bootloc', 1),
          "<BR><INPUT TYPE=submit NAME=save VALUE=\"$text{'index_saveinitdir'}\"></FORM>";

    print "<HR>\n";
    &footer("/", $text{'index_return'});

} elsif (! -e "$bootdir/firewall.pl") {

    &header($text{'index_title'}, undef, "index_fwfile", 1, 1, undef,
            "Written by<BR>Tim Niemueller".
            "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
    print "<HR><BR>\n",
          "<H3>$text{'index_fwfile'}</H3>\n",
          $text{'index_desc_fwfile'},
          "<BR><BR>\n",
          "<A HREF=\"copy_fwfile.cgi\">$text{'index_copyfwfile'}</A>",
          "<BR><BR>";

    print "<HR>\n";
    &footer("/", $text{'index_return'});

} elsif ( (($config{'mode'} == 1) || ($in{'mode'} eq 'newbie')) &&
         ($in{'mode'} ne 'template') &&
         ($in{'mode'} ne 'expert')) {
    # Newbie mode

    &update_script();

    &header($text{'index_title'}, undef, "newbie", 1, 1, undef,
           "Written by<BR>Tim Niemueller".
           "<BR><A HREF=http://www.niemueller.de>Home://page</A>");


    if ($_DEBUG) {
      foreach $c (@config) {
        print "1: $c->{'name'}<BR>\n",
              "2: $c->{'values'}->[0]<BR>\n";
      }
    }

    my $mode = &get_value('MODE', \@config);

    print "<CENTER>\n<FONT SIZE=+2>",
          ($config{'fwtype'} eq 'router') ? $text{'index_router'} : '',
          ($config{'fwtype'} eq 'personal') ? $text{'index_personal'} : '',
          "</FONT>\n<BR><HR>\n";

    my $fwtype = &get_value('FWTYPE', \@config);
    my $level = &get_value('LEVEL', \@config);

    if (defined($level) || ($in{'select'} eq 'default')) {

      print "<TABLE BORDER=0 CELLPADDING=10>\n<TR>";

      my %colors=( disabled => "FF0000",
                   low      => "FF0000",
                   medium   => "FFFF00",
                   high     => "00FF00",
                   full     => "00FF00"
                   );

      my $u = $ENV{'REMOTE_USER'};
      my $lang = $gconfig{"lang_$u"} ? $gconfig{"lang_$u"} :
		             $gconfig{"lang"} ? $gconfig{"lang"} : "en";


      foreach ('disabled', 'low', 'medium', 'high', 'full') {

        print "<TD ALIGN=center WIDTH=100>",
        (($mode->{'values'}->[0] eq 'newbie') && ($level->{'values'}->[0] eq $_) && ($config{'fwtype'} eq $fwtype->{'values'}->[0])) ?
                     "<TABLE BORDER=0 BGCOLOR=#$colors{$_} NOWRAP><TR><TD>" .
                     "<TABLE BORDER=0 BGCOLOR=white><TR><TD>"
                     : "<A HREF=\"change_level.cgi?level=$_\">",
              "<IMG SRC=\"images/",
              (-e "images/$_.$lang.gif") ? "$_.$lang.gif" : "$_.gif",
              "\" BORDER=0>",
        (($mode->{'values'}->[0] eq 'newbie') && ($level->{'values'}->[0] eq $_) && ($config{'fwtype'} eq $fwtype->{'values'}->[0])) ?
                     "</TD></TR></TABLE></TD></TR></TABLE></TD>" : "</A></TD>";
      }

      print "</TR></TABLE></CENTER>",
            "<A HREF=\"?mode=template\">$text{'index_customize'}</A>",
            "<BR>\n";
    } else {
      # We are in Newbie mode, but a customized firewall is installed
      # This may be a template or expert firewall
      print "<BR><H3>$text{'index_customlevel'}</H3><BR>\n",
            "<TABLE BORDER=0>\n<TR>",
            "<TD><A HREF=\"?mode=template\">$text{'index_customize'}</A></TD>",
            "<TD>&nbsp; &nbsp; &nbsp;</TD>",
            "<TD><A HREF=\"?mode=newbie&select=default\">",
            "$text{'index_default'}</A></TD></TR></TABLE><BR><BR><BR>";
    }

    print "<DIV ALIGN=right><FONT FACE=\"Arial,helvetica\" COLOR=\"#505050\">[ $version ] </FONT></DIV>\n",
          "<HR></CENTER>\n";
    &footer("/", $text{'index_return'});



} elsif ( (($config{'mode'} == 2) || ($in{'mode'} eq 'template')) &&
         ($in{'mode'} ne 'newbie') &&
         ($in{'mode'} ne 'expert')) {

  # Template mode


  &update_script();


  &header($text{'index_title'}, undef, "template", 1, 1, undef,
         "Written by<BR>Tim Niemueller".
         "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
  print "<HR><BR>\n";


  my @combs=&get_iface_combs();
  &terror('index_novalcombs') if (! @combs);

  my $savedidx = &get_index(\@combs);
  my $index = $in{'tab'} ? $in{'tab'} : $savedidx;
  &save_index($index);

	$usercol = defined($gconfig{'cs_header'}) ||
		   defined($gconfig{'cs_table'}) ||
		   defined($gconfig{'cs_page'});

	print "\n<table border=0 cellpadding=0 cellspacing=0 height=20><tr>\n";
	for (my $i = 0; $i < scalar(@combs); $i++) {
		if ($index == $i) {
			print "<td valign=top $cb>", $usercol ? "<br>" :
			  "<img src=/images/lc2.gif>","</td>\n";
			print "<td $cb>&nbsp;<b>",
			      $combs[$i]->{'left'}->{'values'}->[0], " -> ", $combs[$i]->{'right'}->{'values'}->[0],
			      "</b>&nbsp;</td>\n";
			print "<td valign=top $cb>", $usercol ? "<br>" :
			  "<img src=/images/rc2.gif>","</td>\n";
			}
		else {
			print "<td valign=top $tb>", $usercol ? "<br>" :
			  "<img src=/images/lc1.gif alt=\"\">","</td>\n";
			print "<td $tb>&nbsp;",
			      "<a href=/?tab=$i><b>",
			      $combs[$i]->{'left'}->{'values'}->[0], " -> ", $combs[$i]->{'right'}->{'values'}->[0],
            "</b></a>&nbsp;</td>\n";
			print "<td valign=top $tb>", $usercol ? "<br>" :
			  "<img src=/images/rc1.gif alt=\"\">","</td>\n";
			}
		print "<td width=10></td>\n";
		}
	print "</tr></table>\n";


  my %miniserv;
  &get_miniserv_config(\%miniserv);
  my %templates=();
  opendir(TEMPLATES, "$miniserv{'root'}/$module_name/templates") || print "FAILED to open template dir";
    while(my $l = readdir(TEMPLATES)) {
      next if ($l =~ /^\./);
      next if ($l !~  /^(.+)\.rules$/);
      my $templname = $1;
      my %templ = &parse_template($templname);
      for (keys %templ) {
        $templates{$templname}->{$_}++;
      }
    }
  closedir(TEMPLATES);

  my $mode=undef;
  my $masq=undef;
  my $seclnbg="#eaeaea";

  my %set = &parse_set_templates($combs[$index]->{'left'}->{'values'}->[0],
                                 $combs[$index]->{'right'}->{'values'}->[0] );

  print "<TABLE BORDER=0 WIDTH=100% CELLPADDING=0 CELLSPACING=0>\n",
        "<FORM ACTION=save_tmode.cgi METHOD=post>\n",
        "<INPUT TYPE=hidden NAME=left VALUE=\"$combs[$index]->{'left'}->{'values'}->[0]\">\n",
        "<INPUT TYPE=hidden NAME=right VALUE=\"$combs[$index]->{'right'}->{'values'}->[0]\">\n",
        "<INPUT TYPE=hidden NAME=lefttype VALUE=\"$combs[$index]->{'left'}->{'values'}->[1]\">\n",
        "<INPUT TYPE=hidden NAME=righttype VALUE=\"$combs[$index]->{'right'}->{'values'}->[1]\">\n",
        " <TR>\n",
        "<TD BGCOLOR=$seclnbg HEIGHT=30><B>$text{'index_templname'}</B></TD>\n",

        # Left -> Firewall
        "<TD ALIGN=center BGCOLOR=$seclnbg><B>",
        $text{"index_short_$combs[$index]->{'left'}->{'values'}->[1]"},
        " -> ",
        $text{"index_short_fw"},
        "</B></TD>\n",

        # Left -> Right
        "<TD ALIGN=center BGCOLOR=$seclnbg><B>",
        $text{"index_short_$combs[$index]->{'left'}->{'values'}->[1]"},
        " -> ",
        $text{"index_short_$combs[$index]->{'right'}->{'values'}->[1]"},
        "</B></TD>\n",

        # Right -> Firewall
        "<TD ALIGN=center BGCOLOR=$seclnbg><B>",
        $text{"index_short_$combs[$index]->{'right'}->{'values'}->[1]"},
        " -> ",
        $text{"index_short_fw"},
        "</B></TD>\n",

        # Right -> Left
        "<TD ALIGN=center BGCOLOR=$seclnbg><B>",
        $text{"index_short_$combs[$index]->{'right'}->{'values'}->[1]"},
        " -> ",
        $text{"index_short_$combs[$index]->{'left'}->{'values'}->[1]"},
        "</B></TD>\n",

        # FW -> Left
        "<TD ALIGN=center BGCOLOR=$seclnbg><B>",
        $text{"index_short_fw"},
        " -> ",
        $text{"index_short_$combs[$index]->{'left'}->{'values'}->[1]"},
        "</B></TD>\n",


        # FW -> Right
        "<TD ALIGN=center BGCOLOR=$seclnbg><B>",
        $text{"index_short_fw"},
        " -> ",
        $text{"index_short_$combs[$index]->{'right'}->{'values'}->[1]"},
        "</B></TD>\n",

        "</TR>\n";

  my $i=0;
  for (sort (keys %templates)) {
    $i++;
    my $t;
    my $name = $_;
    $name =~ s/^(.+)_(.+)$/$1 \($2\)/ if ($name =~ /_/);

    print "<TR",
          (($i % 2) == 0) ? " BGCOLOR=$seclnbg" : "",
          "><TD",
          (($i % 2) == 0) ? " BGCOLOR=$seclnbg" : "",
          ">",
          "<A onClick='window.open(\"show_desc.cgi?ruleset=$_\", \"help\", ".
          "\"toolbar=no,menubar=no,scrollbars=yes,width=500,height=300,resizable=yes\"); ".
          "return false' href=\"show_desc.cgi?ruleset=$_\">$name</A>",
          "</TD>\n";
    foreach $t ("inside -> firewall", "inside -> outside",
                "outside -> firewall", "outside -> inside",
                "firewall -> inside", "firewall -> outside") {
      my $checked = ($set{$_}->{$long2short{$t}}) ? "CHECKED" : "";
      print "<TD ALIGN=center",
            (($i % 2) == 0) ? " BGCOLOR=$seclnbg" : "",
            ">",
            ($templates{$_}->{$t})
              ? "<INPUT TYPE=checkbox NAME=\"$_-$long2short{$t}\" VALUE=1 $checked> $text{'index_activate'} "
              : "N/A",
         "</TD>";
    }
    print "</TR>\n";
  }


  print "</TABLE><BR>",
        "$text{'index_chkbx_desc'}<BR><BR>\n";

  if ($combs[$index]->{'right'}->{'values'}->[1] eq 'internet') {
    print "<INPUT TYPE=checkbox VALUE=1 NAME=masq ",
          ($masq) ? "CHECKED" : "",
          "> $text{'index_tmpl_masq'} ",
          "(<A onClick='window.open(\"show_desc.cgi?ruleset=Masquerading\", \"help\", ".
          "\"toolbar=no,menubar=no,scrollbars=yes,width=500,height=300,",
          "resizable=yes\"); return false' href=\"show_desc.cgi?ruleset=Masquerading\">",
          "$text{'index_desc'}</A>)<BR><BR>\n",
          "<INPUT TYPE=submit NAME=save VALUE=\"$text{'save'}\">",
          "</FORM>\n",
          "<DIV ALIGN=right><FONT FACE=\"Arial,helvetica\" COLOR=\"#505050\">",
          "[ $version ] </FONT></DIV>\n",
          "<HR>\n";
  }
  if ($config{'mode'} == 1) {
    # called from newbie mode, so return there
    &footer("", $text{'index_nbreturn'});
  } else {
    &footer("/", $text{'index_return'});
  }

} else {
  # Expert Mode
  &update_script();

  &header($text{'index_title'}, undef, "expert", 1, 1, undef,
         "Written by<BR>Tim Niemueller".
         "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
  print "<HR><BR>\n";

  my @policies=&get_by_type('POLICY', \@config);
  my %policies=();

  foreach my $p (@policies) {
    $policies{$p->{'values'}->[0]}{$p->{'values'}->[1]} = $p->{'values'}->[2];
  }

  my @chains=&get_by_type('CHAIN', \@config);
  my %chains=();

  foreach my $c (@chains) {
    if (defined($chains{$c->{'values'}->[0]})) {
      push(@{$chains{$c->{'values'}->[0]}}, $c->{'values'}->[1]);
    } else {
      $chains{$c->{'values'}->[0]} = [$c->{'values'}->[1]];
    }
  }


  foreach my $t (sort keys %builtins) {
    # To make it REALLY efficient (this means to allow me to
    # be really lazy for any additional tables :-) I made this a
    # short loop.



    my %policy=();
    foreach my $chain (@{$builtins{$t}}) {
      $policy{$t}{$chain}=($policies{$t}{$chain}) ? $text{"target_$policies{$t}{$chain}"} : $text{'target_ACCEPT'};
    }

    my %images=();
    my %texts=();
    my %links=();

    foreach $l (@{$chains{$t}}) {
      push(@{$images{$t}}, "images/chain.other.gif");
      push(@{$texts{$t}}, $l);
      push(@{$links{$t}}, "edit_chain.cgi?table=$t&chain=$l");
    }



    print "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb WIDTH=100%>\n",
          " <TR>\n",
          "  <TD $tb WIDTH=100%><B>", $text{"index_$t"}, "</B></TD>\n",
          " </TR>\n",
          "</TABLE>\n",

          "<H3>", $text{"index_std_$t"}, "</H3>",
          "<TABLE BORDER=0 WIDTH=100%>\n",
          " <TR>\n";

    foreach $l (@{$builtins{$t}}) {
      print "  <TD ROWSPAN=2 ALIGN=right>\n",
            "   <TABLE BORDER>\n",
            "    <TR>\n",
            "     <TD><A HREF=\"edit_chain.cgi?table=$t&chain=$l\"><IMG SRC=\"images/chain.", lc($l), ".gif\" BORDER=0></A></TD>\n",
            "    </TR>\n",
            "   </TABLE>\n",
            "  </TD>\n",
            "  <TD><A HREF=\"edit_chain.cgi?table=$t&chain=$l\">", $text{$l}, "</A></TD>\n";
    }

    print " </TR>\n",
          " <TR>\n";

    foreach $l (@{$builtins{$t}}) {
      print "  <TD>$text{'index_standpol'}: $policy{$t}{$l}</TD>\n";
    }

    print " </TR>\n",
          "</TABLE>\n\n",
          "<HR>\n\n";

    print "<H3>", $text{"index_udef_$t"}, "</H3>";
    if (! @{$links{$t}}) {
      print "<B>$text{'index_noudef'}</B><BR><BR>"
    } else {
      &icons_table($links{$t}, $texts{$t}, $images{$t}, 5)
    }

    print "<BR><BR><BR>\n";

  } # End of lazyness




print <<EOM;

<HR>
<TABLE BORDER=0 CELLSPACING=3 CELLPADDING=0 WIDTH=100%>
 <TR>
  <TD ALIGN=center>
   [ <A HREF="create_chain.cgi">$text{'index_chaincreate'}</A> ]
  </TD>
  <TD ALIGN=center>
   [ <A HREF="list_hosts.cgi">$text{'index_list'}</A> ]
  </TD>
  <TD ALIGN=center>
   [ <A HREF="enable_conf.cgi">$text{'index_exec'}</A> ]
  </TD>
  <TD ALIGN=right ROWSPAN=2>
   <FONT FACE="Arial,helvetica" COLOR="#505050">[ v$version ] </FONT>
  </TD>
 </TR>
 </TR>
 <TR>
  <TD ALIGN=center>
   <!-- [ <A HREF=".cgi">$text{'index_'}</A> ] -->
  </TD>
  <TD ALIGN=center>
   <!-- [ <A HREF="import.cgi">$text{'index_import'}</A> ] -->
  </TD>
  <TD ALIGN=center>
   [ <A HREF="edit_raw.cgi">$text{'index_rawedit'}</A> ]
  </TD>
</TABLE>


EOM

  print "<HR>\n";
  &footer("/", $text{'index_return'});

}

## SUBS

sub type_select {
  my $rv="";

  $rv="<SELECT NAME=\"$_[0]\">\n";

  for (internal, external, dmz, internet, vpn, ignore) {
    $rv .= "<OPTION VALUE=\"$_\">".$text{"index_$_"} . "\n";
  }

  $rv .= "</SELECT>\n";

return $rv;
}




### END of index.cgi ###.
