#!/usr/bin/perl
#    IPtables Firewall Webmin Module
#    Copyright (C) 2001 by Tim Niemueller <tim@niemueller.de>
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

require './iptables-lib.pl';

my @config=&parse_config();
my @defif=&get_by_type('INTERFACE', \@config);
my @valif=&get_interfaces();

my $file=&read_file_lines($config{'conffile'});

foreach my $v (@valif) {
  my $line=-1;
  foreach my $d (@defif) {
    if ($d->{'values'}->[0] eq $v) {
      $line=$d->{'line'};
      last;
    }
  }

  my $new="INTERFACE($v, $in{$v})";

  if ($line >= 0) {
    # we found an existing directive, replace it
    splice(@$file, $line, 1, $new);
  } else {
    splice(@$file, 0, 1, ($new, $file->[0]));
  }
}

&flush_file_lines();

&redirect("");

### END of save_interfaces.cgi ###.