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

#    Created  : 08.07.2001


require "./iptables-lib.pl";

@config=&parse_config();
my ($title, $desc, $help, $chain, $table);
my @rules=&get_by_type('RULE', \@config);
my $rule = defined($in{'rule'}) ? $rules[$in{'rule'}] : undef;

if ($rule) {
  if ($in{'mode'} eq 'insert') {
    # Insert a rule
    $title=$text{'erule_title_insert'};
    $table= $rule->{'values'}->[0];
    $chain= $rule->{'values'}->[1];
    $desc=&text('erule_desc_insert', $chain, $table);
    $help="erule_insert";
  } else {
    # OK, edit an existing rule
    $title=$text{'erule_title_edit'};
    $table= $rule->{'values'}->[0];
    $chain= $rule->{'values'}->[1];
    $desc=&text('erule_desc_edit', $chain, $table);
    $help="erule_edit";
  }
} else {
  # Append new rule at end of file
  $title=$text{'erule_title_append'};
  $table= $in{'table'};
  $chain= $in{'chain'};
  $desc=&text('erule_desc_append', $chain, $table);
  $help="erule_append";
}

&header($title, undef, $help, undef, undef, undef,
        "Written by<BR>Tim Niemueller".
        "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
print "<BR><HR>";

print "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb WIDTH=100%>\n",
      " <TR>\n",
      "  <TD $tb WIDTH=100%><B>$desc</B></TD>\n",
      " </TR>\n",
      "</TABLE>\n";


my ($source, $sneg, $sport, $spneg,
   $dest, $dneg, $dport, $dpneg, $tcpflagline );

if (($in{'rule'} ne "") &&
    ($in{'mode'} ne 'insert') &&
    ($in{'mode'} ne 'append') ) {

  # we want to values :-)

 # template: $=$rule->{'values'}->[];

 # Source
 ($source, $sneg)=&param_parse($rule->{'values'}->[3]);
 ($sport, $spneg)=&param_parse($rule->{'values'}->[4]);
 
 ($mac, $macneg) = &param_parse($rule->{'values'}->[12]);
 @mac = split(/:/, $mac);

 # Destination
 ($dest, $dneg)=&param_parse($rule->{'values'}->[5]);
 ($dport, $dpneg)=&param_parse($rule->{'values'}->[6]);

 # protocol
 ($proto, $pneg)=&param_parse($rule->{'values'}->[2]);
 ($icmptype, $icmpneg)=&param_parse($rule->{'values'}->[11]);

 #devices
 ($indev, $indevneg)=&param_parse($rule->{'values'}->[7]);
 ($outdev, $outndevneg)=&param_parse($rule->{'values'}->[8]);

 # options
 $fragmented = $rule->{'values'}->[9];


 # TCP flags
 $tcpflagline = $rule->{'values'}->[10];
 ($flags, $flagsneg)=&param_parse($rule->{'values'}->[10]);
 ($unsetflags, $setflags)=split(/\s+/, $flags);
 @setflags=split(/:/, $setflags);
 @unsetflags=split(/:/, $unsetflags);

 foreach my $flag (@setflags) {
   splice(@unsetflags, &indexof($flag, @unsetflags), 1);
 }

 # Limit stuff
 ($limitrate, $limitrateperiod) = split(/\//, $rule->{'values'}->[15]);
 $limitburst = $limitrate ? $rule->{'values'}->[16] : "";
 $limitburst = "" if (uc($limitburst) eq 'IGNORE');
 $limitrate = "" if (uc($limitrate) eq 'IGNORE');

 # Mark
 ($markvalue, $markmask) = split(/\//, $rule->{'values'}->[17]);
 $markvalue = "" if (uc($markvalue) eq 'IGNORE');

 # Owner
 $uid = ($rule->{'values'}->[18] ne 'IGNORE') ? $rule->{'values'}->[18] : "";
 $gid = ($rule->{'values'}->[19] ne 'IGNORE') ? $rule->{'values'}->[19] : "";
 $pid = ($rule->{'values'}->[20] ne 'IGNORE') ? $rule->{'values'}->[20] : "";
 $sid = ($rule->{'values'}->[21] ne 'IGNORE') ? $rule->{'values'}->[21] : "";

 # State
 $state = $rule->{'values'}->[22];

 # TOS
 $tos = $rule->{'values'}->[24];

 # Target
 $target = $rule->{'values'}->[38];

 # Logging
 ($fac, $pri) = split(/\./, $rule->{'values'}->[25]);
 $logprefix = (uc($rule->{'values'}->[26]) ne 'IGNORE') ? $rule->{'values'}->[26] : "";

 $logtcpseq = $rule->{'values'}->[27];
 $logtcpopt = $rule->{'values'}->[28];
 $logipopt = $rule->{'values'}->[29];

}

$in_dev_select=&device_select(\@config, $indev, 'indev');
$out_dev_select=&device_select(\@config, $outdev, 'outdev');

$shc=&host_chooser_button("source"); # Source Host Chooser
$dhc=&host_chooser_button("dest"); # Destination Host Chooser

print "<FORM ACTION=\"save_rule.cgi\" METHOD=post>\n";

if ($in{'rule'} ne "") {
  if ($in{'mode'} eq 'insert') {
    print "<INPUT TYPE=hidden NAME=mode VALUE=insert>\n";
  } else {
    print "<INPUT TYPE=hidden NAME=mode VALUE=edit>\n";
  }

} else {
  print "<INPUT TYPE=hidden NAME=mode VALUE=append>\n";
}

print "<INPUT TYPE=hidden NAME=\"chain\" VALUE=\"$chain\">\n",
      "<INPUT TYPE=hidden NAME=\"table\" VALUE=\"$table\">\n",
      "<INPUT TYPE=hidden NAME=\"rule\" VALUE=\"$in{'rule'}\">\n",
      "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb>\n",
      " <TR>\n",
      "  <TH $tb COLSPAN=7><B>$text{'erule_basic'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD $cb COLSPAN=7 HEIGHT=3><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=1></TD>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TH $tb><B>$text{'erule_source'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=3 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_dest'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=3 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_proto'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=3 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_iface'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD><B>$text{'erule_hostnet'}:</B><BR><INPUT TYPE=checkbox NAME=\"sneg\" VALUE=1$sneg><B>!</B>\n",
      "      <INPUT TYPE=text NAME=\"source\" SIZE=15 VALUE=\"$source\"> $shc</TD>\n",
      "  <TD><B>$text{'erule_hostnet'}:</B><BR><INPUT TYPE=checkbox NAME=\"dneg\" VALUE=1$dneg><B>!</B>\n",
      "      <INPUT TYPE=text NAME=\"dest\" SIZE=15 VALUE=\"$dest\"> $dhc</TD>\n",
      "  <TD><INPUT TYPE=checkbox NAME=\"pneg\" VALUE=1$pneg><B>!</B> ", &proto_select($proto), "</TD>\n",
      "  <TD><B>$text{'erule_incoming'}:</B><BR><INPUT TYPE=checkbox NAME=\"indevneg\" VALUE=1$devneg><B>!</B> $in_dev_select</TD>\n",
      "  </TD>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD><B>$text{'erule_port'}</B><BR><INPUT TYPE=checkbox NAME=\"spneg\" VALUE=1$spneg><B>!</B>\n",
      "              <INPUT TYPE=text NAME=\"sport\" SIZE=10 VALUE=\"$sport\"> $spc</TD>\n",
      "  <TD><B>$text{'erule_port'}</B></B><BR><INPUT TYPE=checkbox NAME=\"dpneg\" VALUE=1$dpneg><B>!</B>",
      "              <INPUT TYPE=text NAME=\"dport\" SIZE=10 VALUE=\"$dport\"> $dpc</TD>\n",
      "  <TD><B>$text{'erule_icmptype'}</B><BR><INPUT TYPE=checkbox NAME=\"icmpneg\" VALUE=1$icmpneg><B>!</B> ", &icmptype_select($icmptype), "</TD>\n",
      "  <TD><B>$text{'erule_outgoing'}:</B><BR><INPUT TYPE=checkbox NAME=\"outdevneg\" VALUE=1$devneg><B>!</B> $out_dev_select</TD>\n",
      "  <!-- <TD><CENTER><B>$text{'erule_tos'}</B></CENTER>$tos_select</TD> -->\n",
      " </TR>\n",
      "</TABLE>\n",
      
      "<BR>\n",
      
      "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb>\n",
      " <TR>\n",
      "  <TH $tb COLSPAN=7><B>$text{'erule_extended'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD $cb COLSPAN=7 HEIGHT=3><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=1></TD>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TH $tb><B>$text{'erule_fragment'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_macsource'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=5 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb COLSPAN=3><B>$text{'erule_tcpflags'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD>", &yni_select('fragment', $fragmented), "</TD>\n",
      "  <TD><INPUT TYPE=checkbox NAME=\"macneg\" VALUE=1$macneg><B>!</B>\n",
      "      <INPUT TYPE=text NAME=\"mac1\" SIZE=2 MAXSIZE=2 VALUE=\"$mac[0]\"> :\n",
      "      <INPUT TYPE=text NAME=\"mac2\" SIZE=2 MAXSIZE=2 VALUE=\"$mac[1]\"> :\n",
      "      <INPUT TYPE=text NAME=\"mac3\" SIZE=2 MAXSIZE=2 VALUE=\"$mac[2]\"> :\n",
      "      <INPUT TYPE=text NAME=\"mac4\" SIZE=2 MAXSIZE=2 VALUE=\"$mac[3]\"> :\n",
      "      <INPUT TYPE=text NAME=\"mac5\" SIZE=2 MAXSIZE=2 VALUE=\"$mac[4]\"> :\n",
      "      <INPUT TYPE=text NAME=\"mac6\" SIZE=2 MAXSIZE=2 VALUE=\"$mac[5]\">\n",
      "  </TD>\n",
      "  <TD ROWSPAN=4><INPUT TYPE=radio NAME=\"tcpflagstype\" VALUE=1",
      ((uc($tcpflagline) eq 'IGNORE') || ! $tcpflagline) ? " CHECKED" : "",
      "> $text{'lib_ignore'}<BR>\n",
      "      <INPUT TYPE=radio NAME=\"tcpflagstype\" VALUE=2",
      (uc($tcpflagline) eq 'ALL') ? " CHECKED" : "",
      "> $text{'erule_tcpf_all'}<BR>\n",
      "      <INPUT TYPE=radio NAME=\"tcpflagstype\" VALUE=3",
      (uc($tcpflagline) eq 'NONE') ? " CHECKED" : "",
      "> $text{'erule_tcpf_none'}<BR>\n",
      "      <INPUT TYPE=radio NAME=\"tcpflagstype\" VALUE=4",
      ($tcpflagline && (uc($tcpflagline) !~ /^(IGNORE|NONE|ALL)$/)) ? " CHECKED" : "",
      "> $text{'erule_tcpf_selected'}<BR>\n",
      "<INPUT TYPE=checkbox NAME=\"tcpflagsneg\" VALUE=1$flagsneg> <B>!</B>\n",
      "  </TD>\n",
      "  <TD ROWSPAN=4><B>$text{'erule_setflags'}</B><BR>\n",
      "      <SELECT NAME=\"settcpflags\" MULTIPLE SIZE=6>\n";

foreach my $flag ('SYN', 'ACK', 'FIN', 'RST', 'URG', 'PSH') {
  print "<OPTION VALUE=$flag",
        (&indexof($flag, @setflags) >= 0) ? " SELECTED" : "",
        ">$flag\n";
}

print "      </SELECT>\n",
      "  </TD>\n",
      "  <TD ROWSPAN=4><B>$text{'erule_unsetflags'}</B><BR>\n",
      "      <SELECT NAME=\"unsettcpflags\" MULTIPLE SIZE=6>\n";

foreach my $flag ('SYN', 'ACK', 'FIN', 'RST', 'URG', 'PSH') {
  print "<OPTION VALUE=$flag",
        (&indexof($flag, @unsetflags) >= 0) ? " SELECTED" : "",
        ">$flag\n";
}

print "      </SELECT>\n",
      "  </TD>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD $cb COLSPAN=3 HEIGHT=3><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=1></TD>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TH $tb COLSPAN=3><B>$text{'erule_limit'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD><B>$text{'erule_limitburst'}:</B><BR><INPUT TYPE=text NAME=\"limitburst\" SIZE=3 MAXSIZE=3 VALUE=\"$limitburst\"></TD>\n",
      "  <TD WIDTH=3 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TD><B>$text{'erule_limitrate'}:</B><BR>",
      "      <INPUT TYPE=text NAME=\"limitrate\" SIZE=3 MAXSIZE=3 VALUE=\"$limitrate\"> / \n",
      "      <SELECT NAME=\"limitrateperiod\">\n";

foreach my $p ('second', 'minute', 'hour', 'day') {
  print "<OPTION VALUE=$p",
        (lc($limitrateperiod) eq $p) ? " SELECTED" : "",
        ">", $text{"erule_limitrateperiod_$p"};
}

print "</SELECT>\n",
      " </TR>\n",

      " <TR>\n",
      "  <TD $cb COLSPAN=7 HEIGHT=3><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=1></TD>\n",
      " </TR>\n",

      " <TR>\n",
      "  <TH $tb><B>$text{'erule_state'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_tos'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=5 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb COLSPAN=3><B>$text{'erule_mark'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD>", &state_select('state', $state), "</TD>\n",
      "  <TD>", &tos_select('tos', $tos), "</TD>\n",
      "  <TD COLSPAN=3><B>$text{'erule_mark_valuemask'}</B><BR>",
      "<INPUT TYPE=text NAME=\"markvalue\" SIZE=3 MAXSIZE=3 VALUE=\"$markvalue\"> / ",
      "<INPUT TYPE=text NAME=\"markmask\" SIZE=3 MAXSIZE=3 VALUE=\"$markmask\">",
      "  </TD>\n",
      " </TR>\n",
      "</TABLE>\n",

      "<BR>\n",

      "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb>\n",
      " <TR>\n",
      "  <TH $tb COLSPAN=7><B>$text{'erule_owner'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD $cb COLSPAN=7 HEIGHT=3><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=1></TD>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TH $tb><B>$text{'erule_uid'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_gid'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_pid'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_sid'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD><INPUT TYPE=text SIZE=5 MAXSIZE=5 NAME=\"uid\" VALUE=\"$uid\"></TD>\n",
      "  <TD><INPUT TYPE=text SIZE=5 MAXSIZE=5 NAME=\"gid\" VALUE=\"$gid\"></TD>\n",
      "  <TD><INPUT TYPE=text SIZE=5 MAXSIZE=5 NAME=\"pid\" VALUE=\"$pid\"></TD>\n",
      "  <TD><INPUT TYPE=text SIZE=5 MAXSIZE=5 NAME=\"sid\" VALUE=\"$sid\"></TD>\n",
      " </TR>\n",
      "</TABLE>\n",

      "<BR>\n",

      "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb>\n",
      " <TR>\n",
      "  <TH $tb COLSPAN=7><B>$text{'erule_logging'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD $cb COLSPAN=7 HEIGHT=3><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=1></TD>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TH $tb><B>$text{'erule_dolog'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_loglevel'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_logprefix'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_extendedlog'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD>", &yn_select('dolog', ($target eq 'LOG') ? 'YES' : 'NO'), "</TD>\n",
      "  <TD>\n",
      "<SELECT NAME=\"syslfac\">\n";

foreach (Default, auth, authpriv, cron, daemon, kern, lpr, mail,
         news, syslog,  user,  uucp, local0, local1, local2, local3,
         local4, local5, local6, local7) {

  print "<OPTION VALUE=$_",
        ($_ eq $fac) ? " SELECTED" : "",
        ">$_\n";

}
print "</SELECT> . ",
      "<SELECT NAME=syslpri>\n";

foreach (Default, debug,  info,  notice, warning,
         err, crit,  alert,  emerg) {

  print "<OPTION VALUE=$_",
        ($_ eq $pri) ? " SELECTED" : "",
        ">$_\n";

}

print "</SELECT>\n",
      "</TD>\n",
      "  <TD><INPUT TYPE=text SIZE=29 MAXSIZE=29 NAME=\"logprefix\" VALUE=\"$logprefix\"></TD>\n",
      "  <TD><INPUT TYPE=checkbox NAME=\"logtcpseq\" VALUE=\"YES\"",
      (uc($logtcpseq) eq 'YES') ? " CHECKED" : "",
      "> $text{'erule_log_tcpseq'} &nbsp;\n",
      "      <INPUT TYPE=checkbox NAME=\"logtcpopt\" VALUE=\"YES\"",
      (uc($$logtcpopt) eq 'YES') ? " CHECKED" : "",
      "> $text{'erule_log_tcpopt'}<BR>\n",
      "      <INPUT TYPE=checkbox NAME=\"logipopt\" VALUE=\"YES\"",
      (uc($logipopt) eq 'YES') ? " CHECKED" : "",
      "> $text{'erule_log_ipopt'}\n",
      "  </TD>\n",
      " </TR>\n",

      " <TR>\n",
      "  <TD $cb COLSPAN=7>$text{'erule_logwarn'}</TD>\n",
      " </TR>\n",
      "</TABLE>\n",

      "<BR>\n",

      "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb>\n",
      " <TR>\n",
      "  <TH $tb COLSPAN=7><B>$text{'erule_modtar'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD $cb COLSPAN=7 HEIGHT=3><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=1></TD>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TH $tb><B>$text{'erule_setmark'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_settos'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_rejtype'}</B></TH>\n",
      "  <TD WIDTH=3 ROWSPAN=2 $cb><IMG SRC=images/dot.gif BORDER=0 HEIGHT=3 WIDTH=3></TD>\n",
      "  <TH $tb><B>$text{'erule_target'}</B></TH>\n",
      " </TR>\n",
      " <TR>\n",
      "  <TD>",
      ($table eq 'mangle') ? "<INPUT TYPE=text SIZE=5 MAXSIZE=5 NAME=\"setmark\">" : $text{'erule_na'},
      "  </TD>\n",
      "  <TD>\n",
      ($table eq 'mangle') ? &tos_select('settos') : $text{'erule_na'},
      "  </TD>\n",
      "  <TD>", &rejecttype_select('rejtype', $rule->{'values'}->[31]), "</TD>\n",
      "  <TD>", &target_select('target', $table, $chain, $target, \@config), "</TD>\n",
      " </TR>\n",
      "</TABLE>\n";



if ($in{'rule'} ne "") {
  if ($in{'mode'} eq 'insert') {
    print "<INPUT TYPE=submit NAME=\"insert\" VALUE=\"",
          " $text{'erule_insert'} \">\n";
  } else {
    print "<INPUT TYPE=submit NAME=\"save\" VALUE=\"",
    " $text{'erule_save'}\">\n";
  }
} else {
  print "<INPUT TYPE=submit NAME=\"append\" VALUE=\"",
        " $text{'erule_append'} \">\n";
}


print "</FORM><BR><HR>\n";



&footer("./edit_chain.cgi?table=$table&chain=$chain", &text('erule_return', $table, $chain));



### END of edit_rule.cgi ###.
