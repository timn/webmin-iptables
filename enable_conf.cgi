#!/usr/bin/perl
#
#    IPtables Firewall Webmin Module
#    Copyright (C) 2001 by Tim Niemueller <tim@niemueller.de>
#    Website: http://www.niemueller.de/
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

#    Created  : 14.12.2001


require "./iptables-lib.pl";

&error_setup($text{'exscript_err'});

if (!-x "$bootdir/firewall.pl") {
  chmod 0700, "$bootdir/firewall.pl";
}

&foreign_check("proc") || &error($text{'exscript_err_procneeded'});
&foreign_require("proc", "proc-lib.pl");

&update_script();

$got = &foreign_call("proc", "safe_process_exec", "$bootdir/firewall.pl",
                     0, 0, STDOUT, undef, 1);

$got && &error(&text('exscript_failed', $got));

&redirect("");

### END of enable_conf.cgi ###.
