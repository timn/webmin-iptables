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

#    Created  : 15.08.2001

require "./iptables-lib.pl";


open(CONF, $config{'conffile'});
 my @conf=<CONF>;
close(CONF);


my @combs=&get_iface_combs();

my $validcomb = 0;
my $left=undef;
my $right=undef;
foreach $c (@combs) {
  if ( ($c->{'left'}->{'values'}->[0] eq $in{'left'}) &&
       ($c->{'right'}->{'values'}->[0] eq $in{'right'}) ) {
    $left = $c->{'left'};
    $right = $c->{'right'};
    $validcomb++;
  }
}

&terror('stm_err_invcomb') if (! $validcomb);

my @newconf = &filter(\@conf, $in{'left'}, $in{'right'});

my @templates = &get_templates();
foreach my $t (@templates) {
  foreach my $d (keys %short2long) {
    if (defined($in{"$t-$d"})) {
      # This template is used in the configuration
      my %templ = &parse_template($t);

      if (defined($templ{$short2long{$d}})) {
        push(@newconf, "# $in{'left'} > $in{'right'} : $t : $d [\n");

        foreach $r (@{$templ{$short2long{$d}}}) {
          my $tmp = &transform_token_net($r, $left, $right);
          if (defined($in{'masq'})) {
            if (($right->{'values'}->[1] eq 'internet') && ($tmp =~ /^MASQ-(.+)$/)) {
              $tmp = $1;
            }
          }
          push(@newconf, "$tmp\n");
        }

        push(@newconf, "# $in{'left'} > $in{'right'} : $t : $d ]\n");
      }
    }
  }
}

open(CONF, "> $config{'conffile'}");
 print CONF @newconf;
close(CONF);


# Now run the script to make the changes active
#if (!-x $config{'conffile'}) {
#  chmod 0700, $config{'conffile'};
#}

# Run that... firewall script
#system($config{'scriptfile'});


&redirect("");


sub filter {
  my @conf = @{$_[0]};
  my $left = $_[1];
  my $right = $_[2];

  my @del=();

  for (my $n=0; $n < scalar(@conf); $n++) {
    if ($conf[$n] =~ /^# $left > $right.*\[/) {
      push(@del, $n);
      $n++;
      while ( ($n < @conf) && ($conf[$n] !~ /^# $left > $right.*\]/) ) {
        push(@del, $n);
        $n++;
      }
      if ($conf[$n] =~ /^# $left > $right.*\]/) {
        push(@del, $n);
      }
    } elsif ($conf[$n] =~ /^LEVEL/) {
      push(@del, $n);
    }

  }

  foreach my $dl (sort { $b <=> $a } @del) {
    splice(@conf, $dl, 1);
  }

return wantarray ? @conf : \@conf;
}

### END of template_save.cgi ###.
