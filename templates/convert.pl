#!/usr/bin/perl
opendir(DIR, ".");
while($d = readdir(DIR)) {
  if ($d =~ /\.rules$/) {
    open(READ, $d) if (-e $d);
     my @lines=<READ>;
    close(READ);

    open(WRITE, ">$d") if (-e $d);
    print "$d:";
    foreach my $l (@lines) {
      chomp $l;
      if ( ($l =~ /MASQ/) && ($l =~ /PREROUTING/)) {
        $l =~ s/PREROUTING/POSTROUTING/g;
        print " PRE->POST ";
        $l =~ /^(\s+)?([A-Z-]+)\((.+)?\)/;
        my $spaces=$1;
        my $prefix = $2;
        my @values=split(/,\s*/, $3);
        if ($values[7] eq 'IGNORE') {
          $values[8] = $values[7];
          $values[7] = 'IGNORE';
          $l="$spaces$prefix(" . join(', ', @values) . ")";
          print " * ";
        }
      }
      print WRITE "$l\n";
    }
    print "\n";
    close(WRITE);
  }
}




