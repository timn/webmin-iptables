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

&terror('erule_err_acl') if (! $access{'erules'});

&terror('erule_err_norule') if ($in{'rule'} eq "");
&terror('erule_err_notable') if (! $in{'table'});
&terror('erule_err_nochain') if (! $in{'chain'});

&terror('erule_err_invstatus') if ($in{'status'} !~ /^(YES|NO)$/);

@config=&parse_config();

my @rules=&get_by_type('RULE', \@config);
my $rule = $rules[$in{'rule'}];

if ( ($rule->{'values'}->[0] ne $in{'table'}) ||
     ($rule->{'values'}->[1] ne $in{'chain'}) ) {
  &error("Cheater! You called this file with faked values!");
}


$file=&read_file_lines($config{'conffile'});

# Warning: Parse Code here again. Maybe we should
# make it a sub!? Warning
$file->[$rule->{'line'}] =~ /^([A-Z]+)\((.+)?\)/;
my $type = $1;
my @values=split(/$conffiledivider\s*/, $2);
$values[39] = $in{'status'};

my $newline = &generate_line(@values);

splice(@$file, $rule->{'line'}, 1, $newline);

&flush_file_lines;

redirect("edit_chain.cgi?table=$in{'table'}&chain=$in{'chain'}");

### END of enable_rule.cgi ###.
