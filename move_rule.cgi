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

#    Created  : 22.07.2001

require "./iptables-lib.pl";

&terror('mrule_err_acl') if (! $access{'erules'});
&terror('mrule_err_norule') if ($in{'rule'} eq "");
&terror('mrule_err_nochain') if ($in{'chain'} eq "");
&terror('mrule_err_notable') if ($in{'table'} eq "");
&terror('mrule_err_invdir') if (($in{'dir'} ne "up") && ($in{'dir'} ne "down"));

@config=&parse_config();

my @rules=&get_by_type('RULE', \@config);
my $rule = $rules[$in{'rule'}];

# Sort lines by line
@rules = sort { $a->{'line'} cmp $b->{'line'} } @rules;

if ( ($rule->{'values'}->[0] ne $in{'table'}) ||
     ($rule->{'values'}->[1] ne $in{'chain'}) ) {
  &error("Cheater! You called this file with faked values!");
}

my $curline = $rule->{'line'};

# Filter out rules that are not in that table and chain
for (my $i = 0; $i < scalar(@rules); $i++) {
  if ( ($rules[$i]->{'values'}->[0] ne $in{'table'}) ||
       ($rules[$i]->{'values'}->[1] ne $in{'chain'}) ) {
    splice(@rules, $i, 1);
  }
}

my $curidx=undef;
for (my $i = 0; $i < scalar(@rules); $i++) {
  $curidx = $i if ($rules[$i]->{'line'} == $curline);
}

&terror('mrule_crit_noidx') if (! defined($curidx));


my $first = $rules[0]->{'line'};
my $last = $rules[scalar(@rules)-1]->{'line'};

my $file=&read_file_lines($config{'conffile'});

if ($in{'dir'} eq "up") {
  # we move a rule up

  # Error: rule is already first in chain
  &terror('mrule_err_top') if ($curidx == 0);

  my @new = ($file->[$rules[$curidx]->{'line'}],
             $file->[$rules[$curidx-1]->{'line'}] );

  splice(@$file, $rules[$curidx]->{'line'}, 1);
  splice(@$file, $rules[$curidx-1]->{'line'}, 1, @new);

} else {
  # we move a rule down

  # Error: Already last rule in chain
  &terror('mrule_err_last') if ($curidx == scalar(@rules)-1);

  my @new = ($file->[$rules[$curidx+1]->{'line'}],
             $file->[$rules[$curidx]->{'line'}] );

  splice(@$file, $rules[$curidx+1]->{'line'}, 1);
  splice(@$file, $rules[$curidx]->{'line'}, 1, @new);


}


&flush_file_lines();

&redirect("edit_chain.cgi?table=$in{'table'}&chain=$in{'chain'}");

### END of move_rule.cgi ###.