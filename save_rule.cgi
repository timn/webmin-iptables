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

#    Created  : 19.07.2001

require "./iptables-lib.pl";

my @config=&parse_config();
my @rules=&get_by_type('RULE', \@config);
my $rule = $rules[$in{'rule'}];


if (($in{'rule'} ne "") &&
    ($in{'mode'} ne 'insert') &&
    ($in{'mode'} ne 'append')) {
  &terror('srule_err_acl2') if (! $access{'erules'});
} else {
  &terror('srule_err_acl')  if (! $access{'crules'});
}


&terror('srule_err_notable') if (! $in{'table'});
&terror('srule_err_nochain') if (! $in{'chain'});

&terror('srule_portproto') if (($in{'sport'} || $in{'dport'}) && ($in{'proto'} !~ /^(tcp|udp)$/i));

&terror('srule_invport') if ($in{'sport'} &&
                             ($in{'sport'} !~ /^\d{1,5}$/) &&
                             (&indexof($in{'sport'}, &get_services_list()) < 0));

&terror('srule_invport') if ($in{'dport'} &&
                             ($in{'dport'} !~ /^\d{1,5}$/) &&
                             (&indexof($in{'dport'}, &get_services_list()) < 0));

&terror('srule_invproto') if ($in{'proto'} && &indexof($in{'proto'}, &get_proto_list()) < 0);

&terror('srule_icmptype') if ($in{'icmptype'} && &indexof($in{'icmptype'}, &get_icmptype_list()) < 0);

&terror('srule_invdev') if ( ($in{'indev'} && &indexof($in{'indev'}, &get_device_list(\@config)) < 0) ||
                             ($in{'outdev'} && &indexof($in{'outdev'}, &get_device_list(\@config)) < 0));

if ($in{'mac1'} && $in{'mac2'} &&
    $in{'mac3'} && $in{'mac4'} &&
    $in{'mac5'} && $in{'mac6'}) {
  $macsource = "$in{'mac1'}:$in{'mac2'}:$in{'mac3'}:$in{'mac4'}:$in{'mac5'}:$in{'mac6'}";
}

if ($in{'markvalue'}) {
  $mark = $in{'markvalue'};
  if ($in{'markprefix'}) {
    $mark .= "/$in{'markprefix'}";
  }
}

if (($in{'syslpri'} ne 'Default') && ($in{'syslfac'} ne 'Default')) {
  $syslog = "$in{'syslfac'}.$in{'syslpri'}";
}

$target = ($in{'dolog'} eq 'YES') ? 'LOG' : $in{'target'};

my $line = &generate_line( $in{'table'}, $in{'chain'},
                           $in{'proto'},
                           $in{'source'}, $in{'sport'},
                           $in{'dest'}, $in{'dport'},
                           $in{'indev'}, $in{'outdev'},
                           $in{'frag'}, $tcpflags,
                           $in{'icmptype'},
                           $macsource,
                           'IGNORE', 'IGNORE',
                           $in{'limitrate'}, $in{'limitburst'},
                           $mark,
                           $in{'uid'}, $in{'gid'},
                           $in{'pid'}, $in{'sid'},
                           $in{'state'}, 'IGNORE',
                           $in{'tos'}, $syslog,
                           $in{'logprefix'}, $in{'logtcpseq'},
                           $in{'logtcpopt'}, $in{'logipopt'},
                           $in{'setmark'} ? $in{'setmark'} : 'IGNORE',
                           $in{'rejecttype'},
                           $in{'settos'} ? $in{'settos'} : 'IGNORE',
                           'IGNORE', 'IGNORE',
                           'NO', 'NO', 'IGNORE',
                           $target, 'YES');


my $file=&read_file_lines($config{'conffile'});

if ($in{'rule'} ne "") {
  if ($in{'mode'} eq 'insert') {
    # we insert a line
    my @new=($file->[$rule->{'line'}], $line);
    splice(@$file, $rule->{'line'}, 1, @new);
  } else { # ($in{'mode'} eq 'edit'))
    # we save an edited line
    splice(@$file, $rule->{'line'}, 1, $line);
  }
} else {
  # we append a line
  push(@$file, $line);
}

&flush_file_lines;


&redirect("edit_chain.cgi?table=$in{'table'}&chain=$in{'chain'}");

### END of save_rule.cgi ###.
