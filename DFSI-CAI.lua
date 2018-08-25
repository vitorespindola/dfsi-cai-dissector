-- Lua Dissector for DFSI CAI based on Thomas Edwards dissector for ST 2110_20
-- Author: Vitor Espindola (vitor.espindola@byne.com.br)
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
    local dfsi_cai = Proto("dfsi_cai", "DFSI CAI")

    local F = dfsi_cai.fields
    F.Signal = ProtoField.uint16("dfsi.cai.signalbit","Signal Bit",base.DEC,nil)
    F.Compact = ProtoField.uint16("dfsi.cai.compact","Compact",base.DEC,nil)
    F.BlockHeaderCount = ProtoField.uint16("dfsi.cai.count","Block Header Count",base.DEC,nil)
    F.Data=ProtoField.bytes("dfsi.cai.data","Data")

    function dfsi_cai.dissector(tvb, pinfo, tree)
        local subtree = tree:add(dfsi_cai, tvb(), "DFSI CAI Data")
        subtree:add(F.Signal, tvb(0,1):bitfield(0,1))

        local compact = tvb(0,1):bitfield(1,1)
        local compact_name = get_compact_name(compact)
        subtree:add(F.Compact, compact, nil, label(compact_name))

        subtree:add(F.BlockHeaderCount, tvb(0,1):bitfield(2,6))
        subtree:add(F.Data,tvb(0,tvb:len()))
    end

    -- register dissector to dynamic payload type dissectorTable
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")
    dyn_payload_type_table:add("dfsi_cai", dfsi_cai)

    -- register dissector to RTP payload type
    local payload_type_table = DissectorTable.get("rtp.pt")
    function dfsi_cai.init()
        payload_type_table:add(100, dfsi_cai)
    end
end

function label(value)
  return "(".. value ..")"
end

function get_compact_name(value)
  local compact_name = "Unknown"

      if value == 0 then compact_name = "Reserved"
  elseif value == 1 then compact_name = "Compact" end

  return compact_name
end
