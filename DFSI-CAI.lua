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
    -- CAI Frame
    F.Signal = ProtoField.uint8("dfsi.cai.signalbit","Signal Bit",base.DEC,nil)
    F.Compact = ProtoField.uint8("dfsi.cai.compact","Compact",base.DEC,nil)
    F.BlockHeaderCount = ProtoField.uint8("dfsi.cai.count","Block Header Count",base.DEC,nil)
    F.P25 = ProtoField.bool("dfsi.cai.p25","P25 specific payload",8,{"Yes","No"},0x80)
    F.BlockPayloadType = ProtoField.uint8("dfsi.cai.payload_type","Block Payload Type",base.DEC,nil)
    -- F.Data = ProtoField.bytes("dfsi.cai.data","Data")

    -- P25 CAI
    F.P25FrameType = ProtoField.uint8("dfsi.cai.p25.frametype","CAI Voice Frame Type",base.HEX,nil)
    F.P25Voice = ProtoField.bytes("dfsi.cai.p25.voice","IMBE Voice Payload")
    F.P25LinkControl = ProtoField.bytes("dfsi.cai.p25.linkcontrol","Link Control")
    F.P25LowSpeedData = ProtoField.bytes("dfsi.cai.p25.lowspeeddata","Low Speed Data")
    F.P25EncryptionSync = ProtoField.bytes("dfsi.cai.p25.encryptionsync","Encryption Sync")
    F.P25ReportErrorTotal = ProtoField.uint8("dfsi.cai.p25.report.error_total","Report Error Total",base.DEC,nil)
    F.P25ReportErrorScaled = ProtoField.uint8("dfsi.cai.p25.report.error_scaled","Report Error Total",base.DEC,nil)
    F.P25ReportMute = ProtoField.bool("dfsi.cai.p25.report.mute","Report Mute")
    F.P25ReportLost = ProtoField.bool("dfsi.cai.p25.report.lost","Report Lost")
    F.P25ReportErrorE4 = ProtoField.uint8("dfsi.cai.p25.report.error_total","Report Error E4",base.DEC)
    F.P25ReportErrorE1 = ProtoField.uint8("dfsi.cai.p25.report.error_total","Report Error E1",base.DEC)
    F.P25SuperFrame = ProtoField.uint8("dfsi.cai.p25.superframe","Super frame",base.DEC)
    F.P25Busy = ProtoField.uint8("dfsi.cai.p25.busy","Busy",base.DEC)

    -- Start of stream
    F.StartStreamNID = ProtoField.uint8("dfsi.cai.startstream.nid","Start of stream NID", base.HEX)
    F.StartStreamNAC = ProtoField.uint8("dfsi.cai.startstream.nac","Start of stream NAC", base.HEX)
    F.StartStreamDUID = ProtoField.uint8("dfsi.cai.startstream.duid","Start of stream DUID", base.HEX)
    F.StartStreamReserve = ProtoField.uint8("dfsi.cai.startstream.reserve","Start of stream reserve", base.DEC)
    F.StartStreamErrorCount = ProtoField.uint8("dfsi.cai.startstream.errorcnt","Start of stream error count", base.DEC)

    -- Voter Report
    F.VoterReportReceiverNumber = ProtoField.uint8("dfsi.cai.voterreport.receiver","Voter Report Receiver Number",base.DEC)
    F.VoterReportDisabled = ProtoField.bool("dfsi.cai.voterreport.disabled","Voter Report Disabled")
    F.VoterReportReceiverStatus = ProtoField.uint8("dfsi.cai.voterreport.status","Voter Report Receiver Status",base.DEC)

    function dfsi_cai.dissector(tvb, pinfo, tree)
        pinfo.cols.protocol:set('DFSI')
        pinfo.cols.info:set('DFSI')

        local subtree = tree:add(dfsi_cai, tvb(), "DFSI CAI")
        subtree:add(F.Signal, tvb(0,1):bitfield(0,1))

        local compact = tvb(0,1):bitfield(1,1)
        subtree:add(F.Compact, compact, nil, label(labels_compact, compact))

        subtree:add(F.BlockHeaderCount, tvb(0,1):bitfield(2,6))

        subtree:add(F.P25, tvb(1,1))

        local p25 = tvb(1,1):bitfield(0,1)
        if p25 == 1 then
            block_pt_type = tvb(1,1):bitfield(1,7)
            subtree:add(F.BlockPayloadType, block_pt_type, nil, label(labels_block_pt, block_pt_type))

            if block_pt_type == BLOCK_PT_CAI_VOICE then
                pinfo.cols.info:append(', CAI Voice')
                dissect_cai_voice(tvb, pinfo, subtree)
            elseif block_pt_type == BLOCK_PT_VOICE_HDR1 then
                pinfo.cols.info:append(', Voice Header Part 1')
                -- TODO
            elseif block_pt_type == BLOCK_PT_VOICE_HDR2 then
                pinfo.cols.info:append(', Voice Header Part 2')
                -- TODO
            elseif block_pt_type == BLOCK_PT_START_STREAM then
                pinfo.cols.info:append(', Start of Stream')
                dissect_start_of_stream(tvb, pinfo, subtree)
            elseif block_pt_type == BLOCK_PT_END_STREAM then
                pinfo.cols.info:append(', End of Stream')
                dissect_start_of_stream(tvb, pinfo, subtree)
            elseif block_pt_type == BLOCK_PT_VOTER_REPORT then
                pinfo.cols.info:append(', Voter Report')
                dissect_voter_report(tvb, pinfo, subtree)
            elseif block_pt_type == BLOCK_PT_VOTER_CONTROL then
                pinfo.cols.info:append(', Voter Control')
                -- TODO
            elseif block_pt_type == BLOCK_PT_TX_KEY_ACK then
                pinfo.cols.info:append(', TX Key Acknowledge')
            elseif block_pt_type >= BLOCK_PT_MANUFACTURER_SPECIFIC_START and block_pt_type <= BLOCK_PT_MANUFACTURER_SPECIFIC_END then
                pinfo.cols.info:append(', Manufacturer specific data')
                -- TODO
            end
        end
    end

    function dissect_cai_voice(tvb, pinfo, tree)
        local cai_frame_type = tvb(2,1):uint()
        pinfo.cols.info:append(', '.. labels_cai_frame_type[cai_frame_type])
        local subtree = tree:add(dfsi_cai, tvb(), labels_cai_frame_type[cai_frame_type])

        subtree:add(F.P25FrameType, cai_frame_type, nil, label(labels_cai_frame_type, cai_frame_type))
        subtree:add(F.P25SuperFrame, tvb(15,1):bitfield(4,2))

        subtree:add(F.P25Voice,tvb(3,11))

        if cai_frame_type >= 100 and cai_frame_type <= 105 then
            subtree:add(F.P25LinkControl,tvb(16,3))
        elseif cai_frame_type == 106 or cai_frame_type == 115 then
            subtree:add(F.P25LowSpeedData,tvb(16,2))
        elseif cai_frame_type >= 109 and cai_frame_type <= 114 then
            subtree:add(F.P25EncryptionSync,tvb(16,3))
        end

        local cai_frame_status = tvb(15,1):bitfield(6,2)
        subtree:add(F.P25Busy, cai_frame_status, nil, label(labels_cai_frame_status, cai_frame_status))

        subtree:add(F.P25ReportErrorTotal, tvb(14,1):bitfield(0,3))
        subtree:add(F.P25ReportErrorScaled, tvb(14,1):bitfield(3,3))
        subtree:add(F.P25ReportMute, tvb(14,1):bitfield(6,1))
        subtree:add(F.P25ReportLost, tvb(14,1):bitfield(7,1))
        subtree:add(F.P25ReportErrorE4, tvb(15,1):bitfield(0,1))
        subtree:add(F.P25ReportErrorE1, tvb(15,1):bitfield(1,3))
    end

    function dissect_start_of_stream(tvb, pinfo, tree)
        tree:add(F.StartStreamNID, tvb(2,2))
        tree:add(F.StartStreamNAC, tvb(2,2):bitfield(0,12))
        tree:add(F.StartStreamDUID, tvb(2,2):bitfield(12,4))
        tree:add(F.StartStreamReserve, tvb(4,1):bitfield(0,4))
        tree:add(F.StartStreamErrorCount, tvb(4,1):bitfield(4,4))
    end

    function dissect_voter_report(tvb, pinfo, tree)
        tree:add(F.VoterReportReceiverNumber, tvb(2,1))
        tree:add(F.VoterReportDisabled, tvb(3,1):bitfield(0,1))

        local voter_report_receiver_status = tvb(3,1):bitfield(1,7)
        tree:add(F.VoterReportReceiverStatus, voter_report_receiver_status, nil, label(labels_voter_report_status, voter_report_receiver_status))
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


function label(labels, value, default)
    if default == nil then
        default = "Unknown"
    end

    local l = labels[value]
    if l == nil then
        l = default
    end

    return "(".. l ..")"
end

BLOCK_PT_CAI_VOICE = 0
BLOCK_PT_VOICE_HDR1 = 6
BLOCK_PT_VOICE_HDR2 = 7
BLOCK_PT_START_STREAM = 9
BLOCK_PT_END_STREAM = 10
BLOCK_PT_VOTER_REPORT = 12
BLOCK_PT_VOTER_CONTROL = 13
BLOCK_PT_TX_KEY_ACK = 14
BLOCK_PT_MANUFACTURER_SPECIFIC_START = 63
BLOCK_PT_MANUFACTURER_SPECIFIC_END = 127

labels_compact = {}
labels_compact[0] = "Reserved"
labels_compact[1] = "Compact"

labels_block_pt = {}
labels_block_pt[0] = "CAI Voice"
labels_block_pt[6] = "Voice Header Part 1"
labels_block_pt[7] = "Voice Header Part 2"
labels_block_pt[9] = "Start of Stream"
labels_block_pt[10] = "End of Stream"
labels_block_pt[12] = "Voter Report"
labels_block_pt[13] = "Voter Control"
labels_block_pt[14] = "TX Key Acknowledge"
-- TODO
-- 63-127 – Manufacturer Specific

labels_cai_frame_type = {}
labels_cai_frame_type[98] = "IMBE Voice 1"
labels_cai_frame_type[99] = "IMBE Voice 2"
labels_cai_frame_type[100] = "IMBE Voice 3 + Link Control"
labels_cai_frame_type[101] = "IMBE Voice 4 + Link Control"
labels_cai_frame_type[102] = "IMBE Voice 5 + Link Control"
labels_cai_frame_type[103] = "IMBE Voice 6 + Link Control"
labels_cai_frame_type[104] = "IMBE Voice 7 + Link Control"
labels_cai_frame_type[105] = "IMBE Voice 8 + Link Control"
labels_cai_frame_type[106] = "IMBE Voice 9 + Low Speed Data"
labels_cai_frame_type[107] = "IMBE Voice 10"
labels_cai_frame_type[108] = "IMBE Voice 11"
labels_cai_frame_type[109] = "IMBE Voice 12 + Encryption Sync"
labels_cai_frame_type[110] = "IMBE Voice 13 + Encryption Sync"
labels_cai_frame_type[111] = "IMBE Voice 14 + Encryption Sync"
labels_cai_frame_type[112] = "IMBE Voice 15 + Encryption Sync"
labels_cai_frame_type[113] = "IMBE Voice 16 + Encryption Sync"
labels_cai_frame_type[114] = "IMBE Voice 17 + Encryption Sync"
labels_cai_frame_type[115] = "IMBE Voice 18 + Low Speed Data"

labels_cai_frame_status = {}
labels_cai_frame_status[1] = "Inbound Channel is Busy"
labels_cai_frame_status[0] = "Unknown, use for talk-around"
labels_cai_frame_status[2] = "Unknown, use for inbound or outbound"
labels_cai_frame_status[3] = "Inbound Channel is Idle"


labels_voter_report_status = {}
labels_voter_report_status[0] = "NO_SIGNAL"
labels_voter_report_status[1] = "SELECTED"
labels_voter_report_status[2] = "GOOD_P25"
labels_voter_report_status[3] = "GOOD_FM"
labels_voter_report_status[4] = "BAD_P25"
labels_voter_report_status[5] = "BAD_FM"
labels_voter_report_status[6] = "NOT_EQUIPPED"
labels_voter_report_status[7] = "FAILED"
