#!/usr/bin/perl

my $ifconfig = `/sbin/ifconfig ipsec0`;
my @ifconfig = split(/\n/, $ifconfig);

$ifconfig[0] =~ /(([0-9A-F]{2}:){5}[0-9A-F]{2})/;
my $mac = $1;
$ifconfig[1] =~ /((\d{1,3}\.){3}\d{1,3})\D*((\d{1,3}\.){3}\d{1,3})/;
$ifconfig[1] =~ /inet addr:((\d{1,3}\.){3}\d{1,3})/;
my $ip = $1;
$ifconfig[1] =~ /Mask:((\d{1,3}\.){3}\d{1,3})/;
my $mask = $1;
$ifconfig[1] =~ /Bcast:((\d{1,3}\.){3}\d{1,3})/;
my $bc = $1;

print "$ifconfig\n";
print "Mac:   $mac\n";
print "IP:    $ip\n";
print "Mask:  $mask\n";
print "Bcast: $bc\n";
