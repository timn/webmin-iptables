#!/usr/bin/perl
# service_chooser.cgi
# This CGI generated the HTML for choosing a service.
# Created 29.10.1999

require './ipchains-lib.pl';

# Build list of services
@services=&get_services();

&header();

print <<EOM;
<SCRIPT LANGUAGE="JavaScript">
function select(f)
{
 ifield.value = f;
 top.close();
 return false;
}
</SCRIPT>
<TITLE>$text{'schooser_title'}</TITLE>
<TABLE WIDTH=100%>
EOM
 foreach $s (@services) {
  print "<TR>\n";
  print "<TD><a href=\"\" onClick='return select(\"$s->{'name'}\")'>$s->{'name'}</TD>",
        "<TD>$s->{'port'}/$s->{'proto'}</TD>",
        "<TD>$s->{'comment'}</TD></TR>\n";
 }
print "</TABLE>\n</BODY></HTML>";

### END of service_chooser.cgi ###.