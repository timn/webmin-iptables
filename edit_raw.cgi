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
#    Inherited from sendmail/edit_file.cgi

require "./iptables-lib.pl";

&header($text{'rawedit_title'}, undef, "cchain", 1, 1, undef,
       "Written by<BR>Tim Niemueller".
       "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
print "<HR><BR>\n";


open(FILE, $config{'conffile'});
@lines = <FILE>;
close(FILE);


print "<B>$text{'rawedit_desc'}</B><BR><BR>\n",
      "<form action=save_file.cgi method=post>\n",
      "<textarea name=text rows=20 cols=80>",
        join("", @lines),"</textarea><p>\n",
      "<input type=submit value=\"$text{'save'}\"> ",
      "<input type=reset value=\"$text{'rawedit_undo'}\">\n",
      "</form>\n",
      "<hr>\n";

&footer($return, $text{'rawedit_return'});

### END of rawedit.cgi ###.
