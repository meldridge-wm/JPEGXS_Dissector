# JPEGXS_Dissector
JPEGXS TR-08 Dissector

Wireshark dissector in Lua for JPEGXS TR-08 data in RTP

Project Lead: Matthew Eldridge (matthew.eldridge@warnermedia.com)

to use in Wireshark:

Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua

Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal and Global plugin directories. After putting this dissector in the proper folder, "About Wireshark/Plugins" should list "jpeg_xs.lua"

In Wireshark Preferences, under "Protocols/JPEG_XS", set dynamic payload type

Capture packets of JPEG_XS TR-08

"Decode As" those UDP packets as RTP

You will now see the JPEGXS Data dissection of the RTP payload

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
