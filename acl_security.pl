
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

#    Created  : 10.03.2000


require "./ipchains-lib.pl";

# acl_security_form(&options)
# Output HTML for editing security options for the apache module
sub acl_security_form
{

print "<TR><TD>$text{'acl_cchains'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"cchains\" VALUE=\"1\"", ($_[0]->{'cchains'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"cchains\" VALUE=\"0\"", ($_[0]->{'cchains'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_echains'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"echains\" VALUE=\"1\"", ($_[0]->{'echains'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"echains\" VALUE=\"0\"", ($_[0]->{'echains'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_dchains'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"dchains\" VALUE=\"1\"", ($_[0]->{'dchains'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"dchains\" VALUE=\"0\"", ($_[0]->{'dchains'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_crules'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"crules\" VALUE=\"1\"", ($_[0]->{'crules'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"crules\" VALUE=\"0\"", ($_[0]->{'crules'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_erules'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"erules\" VALUE=\"1\"", ($_[0]->{'erules'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"erules\" VALUE=\"0\"", ($_[0]->{'erules'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_drules'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"drules\" VALUE=\"1\"", ($_[0]->{'drules'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"drules\" VALUE=\"0\"", ($_[0]->{'drules'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_chosts'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"chosts\" VALUE=\"1\"", ($_[0]->{'chosts'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"chosts\" VALUE=\"0\"", ($_[0]->{'chosts'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_ehosts'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"ehosts\" VALUE=\"1\"", ($_[0]->{'ehosts'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"ehosts\" VALUE=\"0\"", ($_[0]->{'ehosts'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_dhosts'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"dhosts\" VALUE=\"1\"", ($_[0]->{'dhosts'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"dhosts\" VALUE=\"0\"", ($_[0]->{'dhosts'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_bootup'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"bootup\" VALUE=\"1\"", ($_[0]->{'bootup'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"bootup\" VALUE=\"0\"", ($_[0]->{'bootup'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_rewrite'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"rewrite\" VALUE=\"1\"", ($_[0]->{'rewrite'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"rewrite\" VALUE=\"0\"", ($_[0]->{'rewrite'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

print "<TR><TD>$text{'acl_delete'}</TD>";
print "<TD><INPUT TYPE=radio NAME=\"delete\" VALUE=\"1\"", ($_[0]->{'delete'}) ? " CHECKED" : "", "> $text{'yes'} ";
print "<INPUT TYPE=radio NAME=\"delete\" VALUE=\"0\"", ($_[0]->{'delete'}) ? "" : " CHECKED", "> $text{'no'}</TD><TR>\n";

}

# acl_security_save(&options)
# Parse the form for security options for the apache module
sub acl_security_save
{

$_[0]->{'cchains'} = $in{'cchains'};
$_[0]->{'echains'} = $in{'echains'};
$_[0]->{'dchains'} = $in{'dchains'};

$_[0]->{'crules'} = $in{'crules'};
$_[0]->{'erules'} = $in{'erules'};
$_[0]->{'drules'} = $in{'drules'};

$_[0]->{'chosts'} = $in{'chosts'};
$_[0]->{'ehosts'} = $in{'ehosts'};
$_[0]->{'dhosts'} = $in{'dhosts'};

$_[0]->{'bootup'} = $in{'bootup'};
$_[0]->{'rewrite'} = $in{'rewrite'};
$_[0]->{'delete'} = $in{'delete'};

}

### END.