#!/usr/bin/perl
#
#    IPtables Firewalling Webmin Module
#    Copyright (C) 1999-2001 by Tim Niemueller <tim@niemueller.de>
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

#    Created  : 02.10.2001


require "./iptables-lib.pl";

&terror('dchain_err_acl') if (! $access{'drules'});
&terror('dchain_err_notable') if (! $in{'table'});
&terror('dchain_err_nochain') if (! $in{'chain'});

@config=&parse_config();

my @chains=&get_by_type('CHAIN', \@config);
my @rules=&get_by_type('RULE', \@config);


foreach my $c (@chains) {
  if ( ($c->{'values'}->[0] eq $in{'table'}) &&
       ($c->{'values'}->[1] eq $in{'chain'}) ) {
    # We found the chain we want to delete
    my @del=();
    for (my $i=0; $i < scalar(@rules); $i++) {
      if ( ($rules[$i]->{'values'}->[0] eq $in{'table'}) &&
           ($rules[$i]->{'values'}->[1] eq $in{'chain'}) ) {
        # we have to delete this rule, it belongs to the chain
        push(@del, $rules[$i]->{'line'});
      }
    }

    # OK, delete the rules and the chain, reverse sort the
    # array of line numbers so that we delete from end to begin
    # to avoid problems (line number would change, if you delete
    # an earlier line...).
    push(@del, $c->{'line'});
    @del = reverse sort @del;

    my $file = &read_file_lines($config{'conffile'});
    foreach my $d (@del) {
      splice(@$file, $d, 1);
    }
    &flush_file_lines();
  }
}

@config=&parse_config();
my $file = &read_file_lines($config{'conffile'});

@rules=&get_by_type('RULE', \@config);

foreach my $r (@rules) {
  if ($r->{'values'}->[38] eq $in{'chain'}) {
    $r->{'values'}->[38] = 'ACCEPT';
    $file->[$r->{'line'}] = &generate_line(@{$r->{'values'}});
  }
}
&flush_file_lines();

&redirect("");

### END of delete_chain.cgi ###.