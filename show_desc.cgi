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

#    Created  : 01.07.2001

require "./iptables-lib.pl";

my %miniserv;
&get_miniserv_config(\%miniserv);

my $u = $ENV{'REMOTE_USER'};
my $lang = $gconfig{"lang_$u"} ? $gconfig{"lang_$u"} :
		       $gconfig{"lang"} ? $gconfig{"lang"} : "en";

if (! (-f "$miniserv{'root'}/$module_name/descriptions/$lang/$in{'ruleset'}" ||
       -f "$miniserv{'root'}/$module_name/descriptions/en/$in{'ruleset'}") ) {
  &error("$miniserv{'root'}/$module_name/descriptions/$lang/$in{'ruleset'}");
  &terror('desc_err_notfound');
}

my $name = $in{'ruleset'};
if ($name =~ /_/) {
  $name =~ /^(.+)_(.+)$/;
  $name = "$1 ($2)";
}


&header("Ruleset Description - $name");
print "<H3>$name</H3>\n";

if (-e "$miniserv{'root'}/$module_name/descriptions/$lang/$in{'ruleset'}") {
  $file = "$miniserv{'root'}/$module_name/descriptions/$lang/$in{'ruleset'}";
} else {
  $file = "$miniserv{'root'}/$module_name/descriptions/en/$in{'ruleset'}";
}

my @rules = ();
open(DESC, $file);
  print <DESC>;
close(DESC);


print "<BR><BR><BR><HR>\n";
print "<FORM><INPUT TYPE=button onClick='top.close(); return false' VALUE=$text{'desc_close'}></FORM>";


&footer();

### END of desc.cgi ###.
