#!/usr/bin/perl
#
#    IPchains Firewalling Webmin Module
#    Copyright (C) 1999-2000 by Tim Niemueller
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

#    Created  : 10.10.1999


require "./ipchains-lib.pl";

if (! $access{'dchains'}) { &error($text{'delchain_err_acl'}) }
if ($in{'chain'} eq "") { &error($text{'delchain_err_nochain'}) }


@ps=&parse_script();

$chains=&find_arg_struct('-N', \@ps);

foreach $l (@{$chains}) {
 local($c);
 $c=&find_arg('-N', $l);
 if ($c->{'value'} eq $in{'chain'}) {
  $line=$c->{'line'};
 }
}
if (!$line) { &error(&text('delchain_err_notfound', $in{'chain'})) }

$lines=&read_file_lines($config{'scriptfile'});
splice(@{$lines}, $line, 1);
&flush_file_lines();

@ps=&parse_script();
$chainrules=&find_chain_struct($in{'chain'}, \@ps);

while (@{$chainrules}) {
 local($r, $cr);
 $cr=$chainrules->[0];
 $r=&find_arg("-A", $cr);
 $r || ($r=&find_arg('-I', $cr));
 splice(@{$lines}, $r->{'line'}, 1);
 &flush_file_lines();
} continue {
 @ps=&parse_script();
 $chainrules=&find_chain_struct($in{'chain'}, \@ps);
}

&flush_file_lines;

@ps=&parse_script();
$jc=&find_jump_struct($in{'chain'}, \@ps);

while (@{$jc}) {
 local($r);
 $r=&find_arg("-j", $jc->[0]);
 $lines->[$r->{'line'}] = &rm_jump($jc->[0]);
 &flush_file_lines();
} continue {
 @ps=&parse_script();
 $jc=&find_jump_struct($in{'chain'}, \@ps);
}


&flush_file_lines;

&redirect("");

### END of delete_chain.cgi ###.