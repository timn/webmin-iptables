#!/usr/bin/perl
#
#    IPchains Firewalling Webmin Module
#    Copyright (C) 1999-2000 by Tim Niemueller <tim@niemueller.de>
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

#    Created  : 11.10.1999


require "./ipchains-lib.pl";

if ($in{'action'}) { &doit } else { &printscreen }


sub printscreen {

&header($text{'sman_title'}, undef, "sman", undef, undef, undef,
        "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A><BR><A HREF=http://www.niemueller.de>Home://page</A>");
print "<BR><HR>\n";

if ($msg) {
print <<EOM;
<H3>$msg</H3>
<HR>
EOM
} 

print <<EOM;
<TABLE CELLSPACING=0 CELLPADDING=2 BORDER=2>
 <TR>
  <TD $tb COLSPAN=2><B>$text{'sman_header'}</A></TD>
 </TR>
 <TR>
  <TD $cb COLSPAN=2>$text{'sman_confpath'} $config{'scriptfile'}<BR><BR><B>
EOM

 if (-e $config{'scriptfile'}) {
  print $text{'sman_exist'};
 } else {
  print $text{'sman_notexist'};
 }

print <<EOM;
  </B><BR>&nbsp;
  </TD>
 </TR>
 <TR>
  <TD $cb><A HREF="$ENV{'SCRIPT_NAME'}?action=create">$text{'sman_create'}</A></TD>
  <TD $cb>$text{'sman_createdesc'}</TD>
 </TR>
 <TR>
 <TR>
  <TD $cb><A HREF="$ENV{'SCRIPT_NAME'}?action=execute">$text{'sman_execute'}</A></TD>
  <TD $cb>$text{'sman_executedesc'}</TD>
 </TR>
  <TD $cb><A HREF="$ENV{'SCRIPT_NAME'}?action=bootup">$text{'sman_bootup'}</A></TD>
EOM
print "  <TD $cb>".&text('sman_bootupdesc', $config{'bootloc'})."</TD>";

print <<EOM;
 </TR>
 <TR>
  <TD $cb><A HREF="$ENV{'SCRIPT_NAME'}?action=rembootup">$text{'sman_rembootup'}</A></TD>
  <TD $cb>$text{'sman_rembootupdesc'}</TD>
 </TR>
 <TR>
  <TD $cb><A HREF="$ENV{'SCRIPT_NAME'}?action=delete">$text{'sman_delete'}</A></TD>
  <TD $cb>$text{'sman_deletedesc'}</TD>
 </TR>
</TABLE>

EOM

print "<BR><HR>\n";

&footer("./", $text{'sman_return'});

}


sub doit {
 if (!$in{'action'}) {
  &error($text{'sman_err_what'});
 } elsif ($in{'action'} eq "create") {
  if ((-e $config{'scriptfile'}) && !$in{'confirmed'}) {
   if (! $access{'rewrite'}) { &error($text{'sman_err_acl_rewrite'}) }
   &header($text{'sman_title'}, undef, undef, 1, undef, undef,
        "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A><BR><A HREF=http://www.niemueller.de>Home://page</A>");
   print "<BR><HR>\n";
   print "<H3>$text{'sman_err_exists'}</H3>\n";
   print "<FORM ACTION=\"$ENV{'SCRIPT_NAME'}\" METHOD=POST>\n";
   print "<INPUT TYPE=hidden NAME=\"confirmed\" VALUE=1>\n";
   print "<INPUT TYPE=hidden NAME=\"action\" VALUE=\"create\">\n";
   print "<INPUT TYPE=submit VALUE=\"$text{'sman_rewrite'}\">\n";
   print "</FORM><HR>\n";
   &footer("script_manager.cgi", $text{'sman_smanret'});
   exit;
  }

  &create_basic_script($config{'scriptfile'}) || &error($text{'sman_err_write'});

  $msg=$text{'sman_createsucc'};

 } elsif ($in{'action'} eq "execute") {

   if (!-x $config{'scriptfile'}) {
    chmod 0700, $config{'scriptfile'};
    $msg="$text{'sman_msg_exec'}<BR>";
   }

   &foreign_check("proc") || &error($text{'sman_err_procneeded'});
   &foreign_require("proc", "proc-lib.pl");

   $got = &foreign_call("proc", "safe_process_exec", $config{'scriptfile'},
                        0, 0, STDOUT, undef, 1);

   if ($got) {
    $msg .= "$text{'sman_exec_err'} $got";
   } else {
     $msg .= $text{'sman_exec_ok'};
   }

 } elsif ($in{'action'} eq "bootup") {
   if (! $access{'bootup'}) { &error($text{'sman_err_acl_bootup'}) }
   if (!-e $config{'scriptfile'}) { &error(&text('sman_err_nofile', $config{'scriptfile'})) }
  ($dirpath,$basename) = ($config{'scriptfile'} =~ m#^(.*/)?(.*)#);
  ($config{'scriptfile'} =~ /^$config{'bootloc'}\/$basename$/) || &error(&text('sman_err_bootloc', $config{'bootloc'}));
  &foreign_check('init') || &error($text{'smna_err_init'});
  &foreign_require('init', 'init-lib.pl');

  if (! &foreign_call('init', 'action_levels', 'S', $basename)) {
   if (!-x $config{'scriptfile'}) {
    chmod 0700, $config{'scriptfile'};
    $msg="$text{'sman_msg_exec'}<BR>";
   }
   foreach $i (3,4,5) {
    &foreign_call('init', 'add_rl_action', $basename, $i, 'S', 50);
    &foreign_call('init', 'add_rl_action', $basename, $i, 'K', 50);
   }
  } else {
   &error($text{'sman_err_init1'});
  }

  $msg .= $text{'sman_bootupsucc'};

 } elsif ($in{'action'} eq "rembootup") {
   if (!-e $config{'scriptfile'}) { &error(&text('sman_err_nofile', $config{'scriptfile'})) }
  ($dirpath,$basename) = ($config{'scriptfile'} =~ m#^(.*/)?(.*)#);
  ($config{'scriptfile'} =~ /^$config{'bootloc'}\/$basename$/) || &error(&text('sman_err_bootloc', $config{'bootloc'}));
  &foreign_check('init') || &error($text{'smna_err_init'});
  &foreign_require('init', 'init-lib.pl');

  if (&foreign_call('init', 'action_levels', 'S', $basename)) {
   foreach $i (3,4,5) {
    &foreign_call('init', 'delete_rl_action', $basename, $i, 'S');
    &foreign_call('init', 'delete_rl_action', $basename, $i, 'K');
   }
  } else {
   &error($text{'sman_err_init2'});
  }

  $msg = $text{'sman_rembootupsucc'};

 } elsif ($in{'action'} eq "delete") {
  if (! $access{'delete'}) { &error($text{'sman_err_acl_delete'}) }
  if (!-e $config{'scriptfile'}) { &error(&text('sman_err_nofile', $config{'scriptfile'})) }
  ($dirpath,$basename) = ($config{'scriptfile'} =~ m#^(.*/)?(.*)#);
  ($config{'scriptfile'} =~ /^$config{'bootloc'}\/$basename$/) || &error(&text('sman_err_bootloc', $config{'bootloc'}));
  &foreign_check('init') || &error($text{'smna_err_init'});
  &foreign_require('init', 'init-lib.pl');

  if (&foreign_call('init', 'action_levels', 'S', $basename)) {
   foreach $i (3,4,5) {
    &foreign_call('init', 'delete_rl_action', $basename, $i, 'S');
    &foreign_call('init', 'delete_rl_action', $basename, $i, 'K');
   }
   $msg="$text{'sman_msg_rem'}<BR>";
  }

  `rm -f $config{'scriptfile'}`;

  $msg .= $text{'sman_deletesucc'};

 } else {
  &error($text{'sman_err_unkcom'});
 }

 &printscreen;
}

### END of script_manager.cgi ###.
