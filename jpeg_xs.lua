-- Lua Dissector for JPEG XS
-- Author: Matthew Eldridge (matthew.eldridge@warnermedia.com)
--
-- to use in Wireshark:
-- 1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua
-- 2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
--    and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
--    should list "jpeg_xs.lua"
-- 3) In Wireshark Preferences, under "Protocols", set JPEGXS as dynamic payload type being used
-- 4) Capture packets of JPEGXS
-- 5) "Decode As" those UDP packets as RTP
-- 6) You will now see the JPEGXS Data dissection of the RTP payload
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
--
------------------------------------------------------------------------------------------------
do
    local jpeg_xs = Proto("jpeg_xs", "JPEG_XS")

    local prefs = jpeg_xs.prefs
    prefs.dyn_pt = Pref.uint("JPEG_XS dynamic payload type", 0, "The value > 95")

    local F = jpeg_xs.fields
    
    local interlaced_information = {
        [0] = "The payload is progressively scanned.",
        [1] = "This value is reserved for future use.",
        [2] = "The payload is part of the first JPEG XS picture segment of an interlaced video frame.",
        [3] = "The payload is part of the second JPEG XS picture segment of an interlaced video frame."     
    }

    F.T = ProtoField.bool("jpeg_xs.TransmissionMode","Transmission Mode",8,{"Sequential Mode On","Sequential Mode Off"},128)
    F.K = ProtoField.bool("jpeg_xs.PacketizationMode","Packetization Mode",8,{"Slice Packetization Mode","Codestream Packetization Mode"},64)
    F.L = ProtoField.bool("jpeg_xs.Last","Last Packet",8,{"Last Packet","Not Last Packet"},32)
    F.I = ProtoField.uint8("jpeg_xs.InterlacedInformation","Interlaced Information",base.DEC,interlaced_information,24)
    F.F = ProtoField.uint16("jpeg_xs.FrameCounter","Frame Counter",base.DEC,nil,1984)
    F.SEP = ProtoField.uint16("jpeg_xs.SEPCounter","SEP Counter",base.DEC,nil,16376)
    F.P = ProtoField.uint16("jpeg_xs.PacketCounter","Packet Counter",base.DEC,nil,2047)
    F.Video_Data=ProtoField.bytes("jpeg_xs.Video_Data","Video Data")
    
    function jpeg_xs.dissector(buffer, pinfo, tree)
        length = buffer:len()
        if length == 0 then return end
        
        pinfo.cols.protocol = jpeg_xs.name
        
        local subtree = tree:add(jpeg_xs, buffer(),"JPEG_XS Data")
        subtree:add(F.T, buffer(0,1))
        subtree:add(F.K, buffer(0,1))
        subtree:add(F.L, buffer(0,1))
        subtree:add(F.I, buffer(0,1))
        subtree:add(F.F, buffer(0,2))
        subtree:add(F.SEP, buffer(1,2))
        subtree:add(F.P, buffer(2,2))
        subtree:add(F.Video_Data, buffer(4))
    end

    -- register dissector to dynamic payload type dissectorTable
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")
    dyn_payload_type_table:add("jpeg_xs", jpeg_xs)

    -- register dissector to RTP payload type
    local payload_type_table = DissectorTable.get("rtp.pt")
    local old_dissector = nil
    local old_dyn_pt = 0
    function jpeg_xs.init()
        if (prefs.dyn_pt ~= old_dyn_pt) then
            if (old_dyn_pt > 0) then
                if (old_dissector == nil) then
                    payload_type_table:remove(old_dyn_pt, jpeg_xs)
                else
                    payload_type_table:add(old_dyn_pt, old_dissector)
                end
            end
            old_dyn_pt = prefs.dyn_pt
            old_dissector = payload_type_table:get_dissector(old_dyn_pt)
            if (prefs.dyn_pt > 0) then
                payload_type_table:add(prefs.dyn_pt, jpeg_xs)
            end
        end
    end
end
