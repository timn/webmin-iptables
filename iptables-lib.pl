#
#    IPtables Firewall Webmin Module Library
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

#    Created  : 22.06.2001

require '../web-lib.pl';
$|=1;
my $needperl="5.6.0";

&init_config();

eval "use $needperl";
&terror('lib_needmodernperl', $needperl, $@) if ($@);

&ReadParse();

our %access=&get_module_acl();
our $cl=$text{'config_link'};
our $version="0.85.1";
our $bootdir=undef;
our $extdhcp=undef;

our $iptables=($config{'iptables_path'}) ? $config{'iptables_path'} : "/sbin/iptables";


## Global definitions, just to make it easier to modify...

our %builtins=();
    $builtins{'filter'} = [ 'INPUT', 'OUTPUT', 'FORWARD' ];
    $builtins{'nat'} = [ 'PREROUTING', 'OUTPUT', 'POSTROUTING' ];

our %tos=("0x00" => $text{'lib_tosnotset'},
          "0x02" => $text{'lib_tosmincost'},
          "0x04" => $text{'lib_tosmaxrel'},
          "0x08" => $text{'lib_tosmaxthr'},
          "0x10" => $text{'lib_tosmindel'});

our @states=('INVALID', 'ESTABLISHED', 'NEW', 'RELATED');

our @rejecttypes=('icmp-net-unreachable', 'icmp-host-unreachable',
                  'icmp-port-unreachable', 'icmp-proto-unreachable',
                  'icmp-net-prohibitedor', 'icmp-host-prohibited');

our @standardtargets=('ACCEPT', 'DROP', 'LOG');
our @standardpolicies = ('ACCEPT', 'DROP');

our $conffiledivider = ',';

our %long2short = ( "inside -> firewall" => "infw",
                    "inside -> outside" => "inout",
                    "outside -> firewall" => "outfw",
                    "outside -> inside" => "outin",
                    "firewall -> inside" => "fwin",
                    "firewall -> outside" => "fwout" );

our %short2long = ( "infw" => "inside -> firewall",
                    "inout" => "inside -> outside",
                    "outfw" => "outside -> firewall",
                    "outin" => "outside -> inside",
                    "fwin" => "firewall -> inside",
                    "fwout" => "firewall -> outside" );


&terror('lib_err_nosupport') if (!-e "/proc/net/ip_tables_names");
&terror('lib_err_iptables', $iptables, $cl) if (!-x $iptables);

if ((! $config{'conffile'}) &&
    ($ENV{'SCRIPT_NAME'} !~ /(index\.cgi|iptables\/|save_config\.cgi)$/)) {
  &error(&text('lib_err_sfcm', $cl))
}

if ((!-e "$config{'conffile'}") &&
    ($ENV{'SCRIPT_NAME'} !~ /(script_manager\.cgi|index\.cgi|save_config\.cgi|iptables\/)$/)) {
  &error(&text('lib_err_sfmiss', $cl));
}


if ($config{'bootloc'}) {
  $bootdir=$config{'bootloc'};
} else {
  # we try to get the information from the init module
  my %initconf;
  &read_env_file("$config_directory/init/config", \%initconf);
  if ($initconf{'init_dir'}) {
    $bootdir=$initconf{'init_dir'};
  } else {
    &error(&text('lib_noinit', $cl)) if ($ENV{'SCRIPT_NAME'} !~ /(index\.cgi|iptables\/|save_config\.cgi)$/);
  }
}






# parse_config()
# parses the config file and returns an array
sub parse_config {

  my @rv=();

  open(CONF, $config{'conffile'});
   my @conf=<CONF>;
  close(CONF);

  for (my $i=0; $i < @conf; $i++) {
    chomp $conf[$i];
    next if ($conf[$i] =~ /^(#.*)?$/);
    if ($conf[$i] =~ /^([A-Z-]+)\((.+)?\)/) {
      my %line=();
      $line{'name'} = $1;
      $line{'line'} = $i;
      my @values=split(/$conffiledivider\s*/, $2);
      map { s/\@;\@/,/g } @values;
      $line{'values'} = \@values;
      push(@rv, \%line);
    } else {
       &terror('lib_parseerror', $i+1);
    }
  }

return wantarray ? @rv : \@rv;
}


# get_by_type($type, \@config)
# returns an array of parsed lines of $type
sub get_by_type {
  my @rv=();
  my @conf=@{$_[1]};
  my $srchtype = $_[0];
  for (my $i; $i < @conf; $i++) {
    push(@rv, $conf[$i]) if ($conf[$i]->{'name'} eq uc($srchtype));
  }

return wantarray ? @rv : \@rv;
}


# get_value(value, \@config)
# Gets a value from the config file. On multiple
# occurrences it returns only the first
sub get_value {
  my $rv=undef;
  my @conf=@{$_[1]};
  my $srchtype=$_[0];

  foreach $c (@conf) {
    if ($c->{'name'} eq uc($srchtype)) {
      $rv=$c;
      last;
    }
  }

return $rv;
}



sub param_parse {

 my @rv=();

 if ($_[0] =~ /^!\s*(.*)/) {
   push(@rv, $1);
   push(@rv, " CHECKED");
 } else {
   push(@rv, $_[0]);
 }

 @rv = () if (uc($rv[0]) eq 'IGNORE');

return wantarray ? @rv : $rv[0];
}



# generate_line
# creates a new RULE line.
sub generate_line {

  my @line=@_;

  for (my $i = 0; $i < 40; $i++) {
    $line[$i] = 'IGNORE' if (! $line[$i]);
  }

  my $rv="RULE(";
     $rv .= join(', ', @line);
     $rv .= ")";

return $rv;
}



# get_interfaces()
# returns an array with devicenames of valid interfaces
sub get_interfaces {

  my @rv=();

  if (&foreign_check('net')) {
    # we use the network configuration module for getting
    # all interfaces

    &foreign_require('net', 'net-lib.pl');
    my @act = &foreign_call('net', 'active_interfaces');
    @act = sort { "$a->{'name'}:$a->{'virtual'}" cmp
                  "$b->{'name'}:$b->{'virtual'}" } @act;
 
    foreach my $a (@act) {
      next if ($a->{'fullname'} eq 'lo');
      push(@rv, $a->{'fullname'});
    }

  } else {
    # we parse the interfaces from the entered list
    defined($config{'netifaces'}) || &terror('lib_err_netmod', $cl);
    my $if=$config{'netifaces'};
    $if=~tr/\s+//;
    my @act=split(/,/, $if);
    foreach my $a (@act) {
      next if ($a eq 'lo');
      push(@rv, $a);
    }
  }

return wantarray ? @rv : \@rv;
}


# create_basic_conf
# arguments:
#  0  file
#  1  operation mode
#  2  level
#  3  fwtype
#  4  masquerading?
#  5  delete existing file?
#  6  keep interface information?
sub create_basic_conf {

  my @ifcs=();
  if ($_[6]) {
    my @config=&parse_config();
    @ifcs=&get_by_type('INTERFACE', \@config);
  }


  if ((! -e $_[0]) || $_[5]) {
    open(CONF, ">$_[0]");
     print CONF "FLUSH()\n",
                "DELCHAIN()\n",
                "FWTYPE(",
                $_[3] ? $_[3] : $config{'fwtype'},
                $_[4] ? ", $_[4]" : "",
                ")\n",
                "LEVEL(",
                $_[2] ? $_[2] : "disabled",
                ")\n",
                "MODE(",
                $_[1] ? $_[1] : "newbie", ")\n";
     if ($_[6]) {
       foreach my $if (@ifcs) {
         print CONF "INTERFACE(" . join(', ', @{$if->{'values'}}) . ")\n";
       }
     }

    close(CONF);
  }               
}

sub write_basics {

  open(IANA, 'ipv4-address-space.txt');
   my @iana = <IANA>;
  close(IANA);

  open(CONF, ">>$_[0]");

  foreach my $l (@iana) {
    if ($l =~ /^(\d{3})(-(\d{3}))?\/8\t+IANA - Reserved/) {
      my $net = int($1);
      my $rangeend = int($3);
      if ($rangeend) {
        for (my $i=$net; $i <= $rangeend; $i++) {
          print CONF "DENY-RULE($i.0.0.0/8)\n";
        }
      } else {
        print CONF "DENY-RULE($net.0.0.0/8)\n";
      }
    }
  }

  close(IANA);
}



# get_iface_combs()
# returns an array of hashes with all valid interface
# combinations
sub get_iface_combs {

  my @rv=();
  my @config=&parse_config();
  my @defif=&get_by_type('INTERFACE', \@config);

  for (my $i = 0; $i < scalar(@defif); $i++) {
    for (my $j = $i+1; $j < scalar(@defif); $j++) {
      if ( ($defif[$i]->{'values'}->[1] eq 'internal') &&
           ($defif[$j]->{'values'}->[1] ne 'ignore') ) {
        # Routing configurations are only interesting for
        # internal nets to some kind of external networks
        my %comb=();
        $comb{'left'} = $defif[$i];
        $comb{'right'} = $defif[$j];
        push(@rv, \%comb);
      } elsif ( ($defif[$j]->{'values'}->[1] eq 'internal') &&
               ($defif[$i]->{'values'}->[1] ne 'ignore') ) {
        # Routing configurations are only interesting for
        # internal nets to some kind of external networks
        my %comb=();
        $comb{'left'} = $defif[$j];
        $comb{'right'} = $defif[$i];
        push(@rv, \%comb);
      }
    }
  }

return wantarray ? @rv : \@rv;
}


# get_index(\@combs)
# returns the last tab index of the template mode page
sub get_index {
  my @combs=@{$_[0]};

  my $idx=0;
  open(INDEX, "$module_config_directory/index");
 	chop($idx = <INDEX>);
	close(INDEX);

return $idx;
}

# save_index(newindex)
# saves the newindex from templ mode page
sub save_index {
  open(INDEX, ">$module_config_directory/index");
   print INDEX "$_[0]\n";
  close(INDEX);
}



sub generate_hostsfile {
 my $file=$_[0];
 
  open(FILE, ">$file") || &terror('lib_err_create', $file);
   print FILE "# IPchains Firewalling - User defined hosts\n";
   print FILE "# Generated by IPchains Firewalling Webmin Module\n";
   print FILE "# Copyright (C) 1999-2000 by Tim Niemueller, GPL\n";
   print FILE "# Created on ", &make_date(time), "\n";
  close(FILE);

}


sub parse_host_line {
  local(%host, $line);
  $line=$_[0];

  ($host{'ip'}, $host{'names'}) = split(/ /, $line, 2);
  ($host{'ip'}, $host{'netmask'}) = split(/\//, $host{'ip'}, 2);
  if (!$host{'netmask'}) { $host{'netmask'} = "32" }
  $host{'orig'} = $$lines[$i];
  $host{'line'} = $_[1];

return %host;
}

sub get_hosts {
 local($file, @rv, $i, $lines);
 $file=$_[0];

 if (!-e $file) { &error(&text('lib_err_host', $file)) }
 $lines = read_file_lines($file);
 @rv=();

 for (my $i=0; $i <= @$lines - 1; $i++)
 {
  local(%host);
  next if ($$lines[$i] =~ m/^#/i);
  $$lines[$i] =~ s/\t/ /g;
  $$lines[$i] =~ s/[ ]{2,}/ /g;
  next if (!$$lines[$i]);
  %host=&parse_host_line($$lines[$i], $i);
  push (@rv, \%host);
 }

return @rv;
}




# parse_level
# Parses the level file. Throws an terror on any problem (no level config
# file, syntax error, not defined for fwtype etc.)
sub parse_level {
  my $level = $_[0];
  my $fwtype = $_[1];

  my %miniserv;
  &get_miniserv_config(\%miniserv);

  my %defs=();

  &terror('lib_err_nolevelfile') if (! -e "$miniserv{'root'}/$module_name/templates/".uc($level).".level");


  open(LEVEL, "$miniserv{'root'}/$module_name/templates/".uc($level).".level");
    my @f=<LEVEL>;
  close(LEVEL);

  for (my $i=0; $i < scalar(@f); $i++) {
    $f[$i] = &unify($f[$i]);
    if ($f[$i] =~ /^(\S+)\s+\{/) {
      my $localfwtype = $1;
      # print "FWT: $localfwtype<BR>\n";
      my %policies=();
      my %dirs=();
      $i++;
      $f[$i] = &unify($f[$i]);
      while(($i < scalar(@f)) && ($f[$i] !~ /^\s*\}/)) {
        if ($f[$i] =~ /^policies \{/) {
          $i++;
          $f[$i] = &unify($f[$i]);
          while(($i < scalar(@f)) && ($f[$i] !~ /^\s*\}/)) {
            if ($f[$i] =~ /(\S+)::(\S+) => (ACCEPT|DROP)/) {
              # print "P: $1 $2 $3<BR>\n";
              $policies{$1}->{$2} = $3;
            }
            $i++;
            $f[$i] = &unify($f[$i]);
          }
        } elsif ($f[$i] =~ /(\S+) =>? \[(.+)\]/) {
          # print "T: $1 => $2<BR>\n";
          my $tmpname = $1;
          my @tmpdirs = split(/\,\s*/, $2);
          $dirs{$tmpname} = \@tmpdirs;
        }
        $i++;
        $f[$i] = &unify($f[$i]);
      }
      my @tmplevel = (\%policies, \%dirs);
      $defs{$localfwtype} = \@tmplevel;
    }
  }

&terror('lib_err_ndeffwtype', $fwtype, $level) if (! defined($defs{$fwtype}));

return @{$defs{$fwtype}};
}



# Parse Template
# parses a template with $name
sub parse_template {

  my $name = $_[0];

  my %miniserv;
  &get_miniserv_config(\%miniserv);

  my %defs=();

  &terror('lib_err_notemplfile') if (! -e "$miniserv{'root'}/$module_name/templates/$name.rules");


  open(RULES, "$miniserv{'root'}/$module_name/templates/$name.rules");
    my @f=<RULES>;
  close(RULES);

  for (my $i=0; $i < scalar(@f); $i++) {
    $f[$i] = &unify($f[$i]);
    if ($f[$i] =~ /^\s*(.+)\s+\{/) {
      my $direction = $1;
      my @rules=();
      $i++;
      $f[$i] = &unify($f[$i]);
      while(($i < scalar(@f)) && ($f[$i] !~ /^\s*\}/)) {
        push(@rules, $f[$i]);
        $i++;
        $f[$i] = &unify($f[$i]);
      }
      $defs{$direction} = \@rules;
    }
  }

return %defs;
}



# parse_set_templates(leftname, rightname)
# parses the configuration file for set templates
sub parse_set_templates {

  my $left = $_[0];
  my $right = $_[1];

  my %rv=();

  open(CONF, $config{'conffile'});
   my @conf = <CONF>;
  close(CONF);

  foreach my $c (@conf) {
    # Next if NOT a comment, we need the comment meta
    # information for the task of this sub.
    next if ($c !~ /^#/);
    if ($c =~ /^# $left > $right : (\S+) : (\S+) \[/) {
      $rv{$1}->{$2} = 1;
    }
  }

return %rv;
}


# get_templates()
# Returns a list with all template names
sub get_templates {

  my %miniserv;
  &get_miniserv_config(\%miniserv);
  my @templates=();
  opendir(TEMPLATES, "$miniserv{'root'}/$module_name/templates") || print "FAILED to open template dir";
    while(my $l = readdir(TEMPLATES)) {
      next if ($l =~ /^\./);
      next if ($l !~  /^(.+)\.rules$/);
      push(@templates, $1);
    }
  closedir(TEMPLATES);

return wantarray ? @templates : \@templates;
}


# Transforms generic INTIP etc. tokens to device
# specific tokens liek eth0IP.
sub transform_token_net {
  my $line = $_[0];
  my $leftdev = $_[1];
  my $rightdev = $_[2];
  my $left = $leftdev->{'values'}->[0];
  my $right = $rightdev->{'values'}->[0];
  

  $line =~ s/\@INTIP\@/\@${left}IP\@/g;
  $line =~ s/\@INTNET\@/\@${left}NET\@/g;

  if (lc($rightdev->{'values'}->[1]) eq 'internet') {
    $line =~ s/\@EXTNET\@/\@INTERNET\@/g;
  } else {
    $line =~ s/\@EXTNET\@/\@${right}NET\@/g;
  }

  $line =~ s/\@EXTIP\@/\@${right}IP\@/g;
  $line =~ s/\@INTDEV\@/$left/g;
  $line =~ s/\@EXTDEV\@/$right/g;

  $line =~ s/\@WEBMINPORT\@/$ENV{'SERVER_PORT'}/g;

return $line;
}


sub update_script {

  if (-e "$bootdir/firewall.pl") {
    my $file = &read_file_lines("$bootdir/firewall.pl");
    for (my $i=0; $i < scalar(@$file); $i++) {
      if ($file->[$i] =~ /^my \$conffile = '(.+)';$/) {
        if ($1 ne $config{'conffile'}) {
          # conf file has changed, update
          $file->[$i] = "my \$conffile = '$config{'conffile'}';";
        }
      }
    }
    &flush_file_lines();
  }
}



#################################################################################
#################################################################################
## List/Select subs
#################################################################################
#################################################################################


sub get_proto_list {
  local($file, @rv, $l, @lines);
  $file = ($config{'proto_file'}) ? $config{'proto_file'} : "/etc/protocols";
 
  (-e $file) || &error(&text('lib_err_protomis', $cl));
 
  open(PROTO, $file);
    @lines=<PROTO>;
  close(PROTO);
  @lines = grep(!/^#/, @lines);

  foreach $l (@lines) {
    local(@proto);
    $l =~ s/\t/ /g;
    $l =~ s/ {2,}/ /g;  
    chomp $l;
    next if (!$l);
    @proto=split(/ /, $l);
    push(@rv, $proto[0]);
  }

return sort @rv; 
}

sub proto_select {
  local(@proto, $p, $rv, $sel);
  $sel=$_[0];

  $rv="<SELECT NAME=\"proto\">\n";
  $rv.="<OPTION VALUE=0>$text{'lib_any'}\n";
  @proto=&get_proto_list();
  foreach $p (@proto) {
    $rv.= "<OPTION VALUE=\"$p\"";
    $rv.= ($p eq $sel) ? " SELECTED" : "";
    $rv.= ">$p\n";
  }
  $rv.="</SELECT>\n";

return $rv;
}


sub get_device_list {
  my @tmp = &get_by_type('INTERFACE', $_[0]);

  my @rv=();

  foreach my $dev (@tmp) {
    push(@rv, $dev->{'values'}->[0]);
  }

return @rv;
}

# device_select(\@config, $dev, $name)
# returns a select with all valid interfaces
sub device_select {

  my @config=@{$_[0]};
  my $sel = $_[1];

  my @devs = &get_by_type('INTERFACE', \@config);

  $rv = "<SELECT NAME=\"$_[2]\">\n";
  $rv .= "<OPTION VALUE=\"\">$text{'lib_any'}\n";

  foreach $d (@devs) {
    next if ($d->{'values'}->[1] eq 'ignore');

    $rv.= "<OPTION VALUE=\"$d->{'values'}->[0]\"";
    $rv.= ($d->{'values'}->[0] eq $sel) ? " SELECTED" : "";
    $rv.= ">$d->{'values'}->[0] (" . $text{"index_short_$d->{'values'}->[1]"} . ")\n";
  }
  $rv.="</SELECT>\n";

return $rv;
}



sub get_icmptype_list {
  my @rv;
  open (CHILD, "$iptables -p icmp -h |");
   while (<CHILD>) {
     chomp;
     push(@rv, $_);
   }
  close(CHILD);

  for (my $i=0; $i<@rv; $i++) {
    $rv[$i] =~ s/^\s+//g;
    if ($rv[$i] =~ /\(/) {
      $rv[$i] = substr($rv[$i], 0, index($rv[$i], '(')-1);
    }
  }

 while ($rv[0] !~ /^Valid ICMP Types:/) {
   splice(@rv, 0, 1);
 }
 splice(@rv, 0, 1);

return wantarray ? @rv : \@rv;
}

# icmptype_select($sel)
# Gives HTML code for select with ICMP types
sub icmptype_select {

  my $sel=$_[0];

  my $rv="<SELECT NAME=\"icmptype\">\n";
  $rv.="<OPTION VALUE=\"\">$text{'lib_icmptsel'}\n";
  my @icmpt=&get_icmptype_list();
  foreach my $i (@icmpt) {
    chomp($i);
    $i =~ s/ //g;
    $rv.= "<OPTION VALUE=\"$i\"";
    $rv.= ($i eq $sel) ? " SELECTED" : "";
    $rv.= ">$i\n";
  }
  $rv.="</SELECT>\n";

return $rv;
}



sub tos_select {

  my $rv="<SELECT NAME=\"$_[0]\">\n";
     $rv .= "<OPTION VALUE=IGNORE>$text{'lib_ignore'}\n";

  for (sort keys %tos) {
    $rv.= "<OPTION VALUE=\"$_\"";
    $rv.= ($_ eq $_[1]) ? " SELECTED" : "";
    $rv.= ">$tos{$_}\n";
  }
  $rv.="</SELECT>\n";

return $rv;
}



sub yni_select {

  my $rv = "<SELECT NAME=\"$_[0]\">\n";
     $rv .= "<OPTION VALUE=ignore>$text{'lib_ignore'}\n";
     $rv .= "<OPTION VALUE=yes";
     $rv .= " SELECTED" if (uc($_[1]) eq 'YES');
     $rv .= ">$text{'yes'}\n";
     $rv .= "<OPTION VALUE=no";
     $rv .= " SELECTED" if (uc($_[1]) eq 'NO');
     $rv .= ">$text{'no'}\n";
     $rv .= "</SELECT>\n";

return $rv;
}




sub yn_select {

  my $rv = "<SELECT NAME=\"$_[0]\">\n";
     $rv .= "<OPTION VALUE=NO";
     $rv .= " SELECTED" if (uc($_[1]) eq 'NO');
     $rv .= ">$text{'no'}\n";
     $rv .= "<OPTION VALUE=YES";
     $rv .= " SELECTED" if (uc($_[1]) eq 'YES');
     $rv .= ">$text{'yes'}\n";
     $rv .= "</SELECT>\n";

return $rv;
}


sub state_select {

  my $rv = "<SELECT NAME=\"$_[0]\">\n";
     $rv .= "<OPTION VALUE=IGNORE>$text{'lib_ignore'}\n";

  foreach my $state (@states) {
    $rv .= "<OPTION";
    $rv .= " SELECTED" if ($_[1] eq $state);
    $rv .= ">$state\n";
  }

  $rv .= "</SELECT>\n";

return $rv;
}


sub table_select {

  my $rv = "<SELECT NAME=\"$_[0]\">\n";

  foreach my $table (sort keys %builtins) {
    $rv .= "<OPTION";
    $rv .= " SELECTED" if ($_[1] eq $table);
    $rv .= ">$table\n";
  }

  $rv .= "</SELECT>\n";

return $rv;
}




sub rejecttype_select {

  my $rv = "<SELECT NAME=\"$_[0]\">\n";
     $rv .= "<OPTION VALUE=IGNORE>$text{'lib_ignore'}\n";

  foreach my $rejtype (@rejecttypes) {
    $rv .= "<OPTION>$rejtype\n";
  }

  $rv .= "</SELECT>\n";

return $rv;
}



sub target_select {

  my $rv;
  my $name = $_[0];
  my $table = $_[1];
  my $chain = $_[2];
  my $target = $_[3];
  my $config = $_[4];

  my @chains=&get_by_type('CHAIN', $config);

  my $rv = "<SELECT NAME=\"$name\">\n";

  foreach my $s (@standardtargets) {
    $rv .= "<OPTION";
    $rv .= " SELECTED" if ($_[3] eq $s);
    $rv .= ">$s\n";
  }

  foreach my $b (@{$builtins{$table}}) {
    next if ($b eq $chain);
    $rv .= "<OPTION";
    $rv .= " SELECTED" if ($target eq $b);
    $rv .= ">$b\n";
  }

  foreach my $c (@chains) {
    next if ($c->{'values'}->[1] eq $chain);
    $rv .= "<OPTION";
    $rv .= " SELECTED" if ($target eq $c->{'values'}->[1]);
    $rv .= ">$c->{'values'}->[1]\n";
  }


  $rv .= "</SELECT>\n";

return $rv;
}





#################################################################################
#################################################################################
## Chooser Functions
#################################################################################
#################################################################################


# service_chooser_button(field, [form])
# Returns HTML for a javascript button for choosing a service
sub service_chooser_button
{
local $form = @_ > 1 ? $_[1] : 0;
return "<input type=button onClick='ifield = document.forms[$form].$_[0]; chooser = window.open(\"service_chooser.cgi\", \"chooser\", \"toolbar=no,menubar=no,scrollbars=yes,width=500,height=300\"); chooser.ifield = ifield' value=\"...\">\n";
}

# host_chooser_button(field, [form])
# Returns HTML for a javascript button for choosing a host
sub host_chooser_button
{
local $form = @_ > 1 ? $_[1] : 0;
return "<input type=button onClick='ifield = document.forms[$form].$_[0]; chooser = window.open(\"host_chooser.cgi\", \"chooser\", \"toolbar=no,menubar=no,scrollbars=yes,width=500,height=300\"); chooser.ifield = ifield' value=\"...\">\n";
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

sub unify {
  my $string=$_[0];
  chomp $string;
  $string =~ s/\t+/ /g;
  $string =~ s/\s+/ /g;
  $string =~ s/^\s+//;

return $string;
}

1;
### END of iptables-lib.cgi ###.
