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

#    Created  : 16.08.2001

#    Description: This file is the "executor" part of the module. It
#                 executes firewall rules that are in the config file.
#                 It "translates" the conf entries into real rules.

# chkconfig: 345 50 50
# description: Firewall Wrapper from the IPtables Firewall Webmin Module
# processname: none
# configfile: see below
# pidfile: none

# Define where to find config file and iptables.
my $conffile = '/etc/iptfw.conf';
my $iptables = 'LANG=C /sbin/iptables';
my $ifconfig = 'LANG=C /sbin/ifconfig';
my $insmod   = '/sbin/insmod';
my $modprobe = '/sbin/modprobe';

my $DEBUG=0;
my @c = &parse_config($conffile);
my @e = ();  # lines to execute
my %if = (); # interface informations

# First we build @e
for (my $i=0; $i < scalar(@c); $i++) {
  # Traverse all rules
  if ($c[$i]->{'name'} eq 'FLUSH') {
    if (scalar(@{$c[$i]->{'values'}})) {
      # we flush named chains
      foreach my $v (@{$c[$i]->{'values'}}) {
        my ($table, $chain) = split(/::/, $v);
        push(@e, "$iptables -t $table -F $chain");
      }
    } else {
      # we flush all chains in all tables
      push(@e, "$iptables -F");
      push(@e, "$iptables -t nat -F");
    }
  } elsif ($c[$i]->{'name'} eq 'DELCHAIN') {
    if (scalar(@{$c[$i]->{'values'}})) {
      # we delete named chains
      foreach my $v (@{$c[$i]->{'values'}}) {
        my ($table, $chain) = split(/::/, $v);
        push(@e, "$iptables -t $table -X $chain");
      }
    } else {
      # we flush all chains in all tables
      push(@e, "$iptables -X");
      push(@e, "$iptables -t nat -X");
    } 
  } elsif ($c[$i]->{'name'} eq 'INTERFACE') {
    # Initialize an interface
    my %iface=();
    my $ifcfgout = `$ifconfig $c[$i]->{'values'}->[0]`;
    my @ifcfgout = split(/\n/, $ifcfgout);
    $ifcfgout[0] =~ /(([0-9A-F]{2}:){5}[0-9A-F]{2})/;
    $iface{'mac'} = $1;
    $ifcfgout[1] =~ /inet addr:((\d{1,3}\.){3}\d{1,3})/;
    $iface{'ip'} = $1;
    $ifcfgout[1] =~ /Mask:((\d{1,3}\.){3}\d{1,3})/;
    $iface{'mask'} = $1;
    if ($ifcfgout[1] =~ /Bcast:((\d{1,3}\.){3}\d{1,3})/) {
      $iface{'bcast'} = $1;
    }

    $if{$c[$i]->{'values'}->[0]} = \%iface;
  } elsif ($c[$i]->{'name'} eq 'DENY-RULE') {
    # We have a deny rule, deny it!
    push(@e, "$iptables -t filter -A INPUT -s $c[$i]->{'values'}->[0] -j DROP");
    push(@e, "$iptables -t filter -A FORWARD -s $c[$i]->{'values'}->[0] -j DROP");
  } elsif ($c[$i]->{'name'} eq 'KERNELMOD') {
    # Wow, load a kernel module.
    if ($c[$i]->{'values'}->[0] eq 'insmod') {
      push(@e, "$insmod $c[$i]->{'values'}->[1] $c[$i]->{'values'}->[2]");
    } else {
      push(@e, "$modprobe $c[$i]->{'values'}->[1] $c[$i]->{'values'}->[2]");
    }
  } elsif ($c[$i]->{'name'} eq 'CHAIN') {
    # Create a chain
    push(@e, "$iptables -t $c[$i]->{'values'}->[0] -N $c[$i]->{'values'}->[1]");
  } elsif ($c[$i]->{'name'} eq 'POLICY') {
    # Set Policy
    push(@e, "$iptables -t $c[$i]->{'values'}->[0] -P $c[$i]->{'values'}->[1] $c[$i]->{'values'}->[2]");
  } elsif ($c[$i]->{'name'} eq 'RULE') {
    # Append a rule.
    push(@e, &generate_rule($c[$i]->{'values'}));
  } elsif ($c[$i]->{'name'} eq 'CONDMULTI-RULE') {
    # We have a multi rule with condition
    my $condtype = $c[$i]->{'values'}->[0];
    my $count = $c[$i]->{'values'}->[1];
    my %conds=();
    my @rules=();
    my @erules=();
    for (my $n=2; (($n < 41) && ($n < scalar(@{$c[$i]->{'values'}}))); $n++) {
      if ($c[$i]->{'values'}->[$n] =~ /\%\%(.+)\%\%(.+)\%\%/) {
        # we have a valid condition
        $conds{$1} = $2;
      }
    }
    $i++;
    if (($i+$count) <= scalar(@c)) {
      # Valid number of condition rules.
      # Push them in @rules
      for (my $n = $i; $n < $i+$count; $n++) {
        push(@rules, $c[$n]);
      }
      $i += $count-1;     # -1 since we incremented some lines above
    }

    for (keys %conds) {
      if ($condtype eq 'system') {
        # Conditions are perl system call
        # print "COND: $_ ( $conds{$_} )\n";
        my @tmp = ();
        @tmp = split(/\n/, qx($conds{$_}));

        # If the command output ends with \n as it usually does
        # we will get a 0 value at the end of the array...
        splice(@tmp, scalar(@tmp)-1, 1) if (! $tmp[scalar(@tmp)-1]);

        foreach my $t (@tmp) {
          foreach my $r (@rules) {
            my @new=@{$r->{'values'}};
            for (my $v=0; $v < scalar(@new); $v++) {
              $new[$v] =~ s/\@$_\@/$t/;
            }
            push(@erules, \@new);
          }
        }
      }
    }

    foreach my $r (@erules) {
      push(@e, &generate_rule($r));
    }

  }
}


if ($DEBUG) {
  # write @e to file
  open(DEBUG, ">DEBUG.txt");
   print DEBUG join("\n", @e);
  close(DEBUG);
} else {
  # execute "@e"
  foreach $c (@e) {
    # print "$c\n";
    system($c);
  }
}

################################################################################
################################################################################
## Subs
################################################################################
################################################################################

# parse_config()
# parses the config file and returns an array.
# taken from iptables-lib.pl and slightly modified.
# Has to be reproduced otherwise we would need to require
# the lib, but then we would get problems with the
# Webmin dependant stuff...
sub parse_config {

  my $confname = $_[0];
  my @rv=();

  open(CONF, $confname);
   my @conf=<CONF>;
  close(CONF);

  for (my $i=0; $i < @conf; $i++) {
    chomp $conf[$i];
    next if ($conf[$i] =~ /^(#.*)?$/);
    if ($conf[$i] =~ /^([A-Z-]+)\((.+)?\)/) {
      my %line=();
      $line{'name'} = $1;
      $line{'line'} = $i;
      my @values=split(/,\s*/, $2);
      map { s/\@;\@/,/g } @values;
      $line{'values'} = \@values;
      push(@rv, \%line);
    } else {
       print "Syntax error in line $i. Aborting";
       exit 0;
    }
  }

return wantarray ? @rv : \@rv;
}



# generate_rule(\@parsed)
# create an iptables call for a rule
sub generate_rule {

  my @values = @{$_[0]};
  my $rv=$iptables;
  my $endterm = "";

  # Define what to prepend to the values in the order
  # as defined in the CONF file. Just to fit my lazyness :-)
  # Sometimes "-m" may get double defined. That is no problem,
  # iptables ignores this.
  my @fields =( "-t", "-A", "-p",
                "-s", "--source-port",
                "-d", "--destination-port",
                "-i", "-o",
                "B-f", "R--tcp-flags",
                "--icmp-type", "--mac-source",
                "", "",
                "-m limit --limit", "-m limit --limit-burst",
                "-m mark --mark",
                "-m owner --uid-owner", "-m owner --did-owner",
                "-m owner --sid-owner", "-m owner --pid-owner",
                "R-m state --state", "",
                "-m tos --tos",
                "T:LOG--log-level", "T:LOG--log-prefix",
                "T:LOG--log-tcp-sequence", "T:LOG--log-tcp-options",
                "T:LOG--log-ip-options",
                "--set-mark", "--reject-type", "--set-tos",
                "T:SNAT--to-source", "T:DNAT--to-destination",
                "T:MASQUERADE--to-ports", "T:REDIRECT--to-ports",
                "B--syn", "-j"
               );

  if (uc($values[39]) eq 'YES') {
    # Remove the active flag.
    splice(@values, 39, 1);
    # Rule is active
    for (my $n=0; ($n < scalar(@values)) && ($n < scalar(@fields)); $n++) {
      # Traverse all values/fields

      # Do not care about IGNORE or empty values or empty fields
      next if (! $values[$n] || (uc($values[$n]) eq 'IGNORE') ||
               ! $fields[$n]);

      if ($fields[$n] =~ /^B(.*)/) {
        # We have a "binary" argument, YES or NO
        my $f = $1;
        if (uc($values[$n]) eq 'YES') {
          $rv .= " $f";
        } else {
          $rv .= " ! $f";
        }
      } elsif ($fields[$n] =~ /^R(.*)/) {
        # Replace colons with commas. This is needed since the
        # comma is the separator of the config file...
        my $f = $1;
        $values[$n] =~ s/:/,/g;
        $rv .= " $f $values[$n]";
      } elsif ($fields[$n] =~ /^T:([A-Z]+)(.*)/) {
        # Check if we have right target. If we have right target, we want this
        # to be appended after the target is called, since we would get an error otherwise
        my $tar = $1;
        my $opt = $2;
        if ($values[38] eq $tar) {
          # YES, we have the right target :-)
          $endterm .= " $opt $values[$n]";
        }
      } else {
        # simple field/value append
        $rv .= " $fields[$n] $values[$n]";
      }
    } # End FOR @values
  } #  else { Rule is disabled. ignore. }

  $rv .= $endterm;

return &fill_tokens($rv);
}# End generate_rule



# fill_tokens
# fills tokens like @eth0IP@ with the appropriate value
sub fill_tokens {

  my $t = $_[0];

  while ($t =~ /\@([A-Za-z0-9:]+)IP\@/) {
    my $dev = $1;
    if (defined($if{$dev})) {
      $t =~ s/\@${dev}IP\@/$if{$dev}->{'ip'}/g;
    } else {
      print "IP Device $dev is not defined in configuration file: Line will be ignored!\n";
    }
  }

  while ($t =~ /\@([A-Za-z0-9:]+)NET\@/) {
    my $dev = $1;
    if ($dev eq 'INTER') {
      $t =~ s/\@INTERNET\@/0.0.0.0\/0/g;
    } elsif (defined($if{$dev})) {
      my $nw = &network($if{$dev}->{'ip'}, $if{$dev}->{'mask'});
      # print "DEV: $dev (IP: $if{$dev}->{'ip'}, Net: $nw, Mask: $if{$dev}->{'mask'})\n";
      $t =~ s/\@${dev}NET\@/$nw\/$if{$dev}->{'mask'}/g;
    } else {
      print "NET Device $dev is not defined in configuration file: Line will be ignored!\n";
    }
  }

  $t =~ s/\@WEBMINPORT\@/$ENV{'SERVER_PORT'}/g;

return $t;
}


sub broadcast {

 my $ipnum = &numberize($_[0]);
 my $nmnum = &numberize($_[1]);
 my $broadcast = &denumberize($ipnum | ~ $nmnum);

return $broadcast;
}

sub network {

 my $ipnum = &numberize($_[0]);
 my $nmnum = &numberize($_[1]);
 my $network = &denumberize($ipnum & $nmnum);

return $network;
}

sub numberize {
 (my $a, my $b, my $c, my $d) = split(/\./, $_[0]);
 return (($a << 24) | ($b << 16) | ($c << 8) | $d);
}

sub denumberize {
 return join('.', ($_[0] & 0xff000000) >> 24,
                  ($_[0] & 0x00ff0000) >> 16,
                  ($_[0] & 0x0000ff00) >> 8,
                  ($_[0] & 0x000000ff) );
}



### END of firewall.pl ###.
