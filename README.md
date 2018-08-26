# DFSI CAI dissector

Wireshark dissector in Lua for DFSI CAI.

This dissector is based on SMPTE ST 2110-20 dissector found in https://github.com/FOXNEOAdvancedTechnology/smpte2110-20-dissector.

## Usage

1. Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua

1. Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins" should list "DFSI-CAI.lua"

1. Decode captured CAI packages using "Decode As" as RTP

1. You will now see the DFSI CAI Data dissection of the RTP payload

## TODO

* Register a dissector for FSC packages
* Handle non CAI voice packages(uLaw voice)
* Dissect Link Control, Encryption Sync and Low Speed Data
* Color for packages with errors
* Voter control
* Voice headers 1 and 2
* Manufacturer specific data

## License

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
