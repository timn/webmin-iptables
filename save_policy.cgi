#!/usr/bin/perl
#
#    IPtables Firewall Webmin Module
#    Copyright (C) 2001 by Tim Niemueller <tim@niemueller.de>
#    Website: http://www.niemueller.de/webmin/module/iptables/
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


&terror('savepol_err_nochain') if ($in{'chain'} eq "");

&terror('spol_invch') if ( &indexof($in{'chain'}, @{$builtins{$in{'table'}}}) < 0 );

@config=&parse_config();

my @policies=&get_by_type('POLICY', \@config);
my %policies=();

my $line = undef;
foreach my $p (@policies) {
  if ( ($p->{'values'}->[0] eq $in{'table'}) &&
       ($p->{'values'}->[1] eq $in{'chain'}) ) {
    $line = $p->{'line'};
  }
}



$lines=&read_file_lines($config{'conffile'});

$newline="POLICY($in{'table'}, $in{'chain'}, $in{'policy'})";

if (defined($line)) {
 # we are changing an existing rule
 $lines->[$line]=$newline;
} else {
 # we are creating a new rule
 push(@$lines, $newline);
}

&flush_file_lines;

redirect("edit_chain.cgi?table=$in{'table'}&chain=$in{'chain'}");

### END of save_policy.cgi ###.
