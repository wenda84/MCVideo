-- @brief   解析MCVideo RTCP中的传输控制协议
-- @author  
-- @version v8.10.20
require("bit32")

local PROTO_NAME = "MCVideo"
local proto_MCVideo = Proto(PROTO_NAME, "MCVideo")
local rtcp_dissector = Dissector.get("rtcp")
local stun_dissector = Dissector.get("stun-udp")
local mc_fields = proto_MCVideo.fields

RTCP_HEAD_SIZE = 12
RTCP_PKT_TYPE_APP_SEPCIFIC = 0xCC

-- filed id映射表，不是特别全，需要的时候在加
local filed_id_table = {}
do
    filed_id_table["Transmission Priority"] = 0
    filed_id_table["Duration"] = 1
    filed_id_table["Reject Cause"] = 2
    filed_id_table["Granted Party's Identity"] = 4
    filed_id_table["Permission to Request the Transmission"] = 5
    filed_id_table["User ID"] = 6
    filed_id_table["Message Sequence Number"] = 8
    filed_id_table["Source"] = 0xa
    filed_id_table["Message Type"] = 0xc
    filed_id_table["Transmission Indicator"] = 0xd
    filed_id_table["SSRC"] = 0xe
    filed_id_table["Result"] = 0xf
    filed_id_table["Message Name"] = 0x10
    filed_id_table["Reception Priority"] = 0x13
end

-- 各字段具体定义
do
    mc_fields.UserID = ProtoField.string(PROTO_NAME .. "UserID", "UserID")
    mc_fields.SSRC = ProtoField.string(PROTO_NAME .. "SSRC", "SSRC")
    mc_fields.MsgSeqNum = ProtoField.uint16(PROTO_NAME .. "MsgSeqNum", "Message Sequence Number")
    mc_fields.TransIndi = ProtoField.string(PROTO_NAME .. "TransmissionIndicator", "Transmission Indicator")
    mc_fields.RejectCause = ProtoField.string(PROTO_NAME .. "RejectCause", "Reject Cause")
    mc_fields.TransPriority = ProtoField.uint8(PROTO_NAME .. "TransPriority", "Transmission Priority")
    mc_fields.Duration = ProtoField.uint8(PROTO_NAME .. "Duration", "Duration")
    mc_fields.Source = ProtoField.uint16(PROTO_NAME .. "Source", "Source")
    mc_fields.MsgName = ProtoField.string(PROTO_NAME .. "MsgName", "Message Name")
    mc_fields.MsgType = ProtoField.uint8(PROTO_NAME .. "MsgType", "Message Type")
    mc_fields.RecepPriority = ProtoField.uint8(PROTO_NAME .. "RecepPriority", "Reception Priority")
    mc_fields.Result = ProtoField.uint16(PROTO_NAME .. "Result", "Result")
end

local function show_support_Dissector()
    local t = Dissector.list()
    print("========================== all Dissector ==========================")
    for _, name in ipairs(t) do
        print(name)
    end

    local dt = DissectorTable.list()
    print("========================== all DissectorTable ==========================")
    for _, name in ipairs(dt) do
        print(name)
    end
end

local function getMCVideoMsgInfo(rtcp_subtype, rtcp_name)
    local ret = "unknown"
    if rtcp_name == "MCV0" then
        if rtcp_subtype == 0 then
            ret = "Transmission Request"
        elseif rtcp_subtype == 0x4 then
            ret = "Receive Media Request"
        end
    elseif rtcp_name == "MCV1" then
        if rtcp_subtype == 0 then
            ret = "Transmission Granted"
        elseif rtcp_subtype == 0x1 then
            ret = "Transmission Reject"
        elseif rtcp_subtype == 0x4 then
            ret = "Transmission Revoke"
        elseif rtcp_subtype == 0x6 then
            ret = "Media Transmission Notification"
        elseif rtcp_subtype == 0x7 then
            ret = "Receive Media Response"
        elseif rtcp_subtype == 0x8 then
            ret = "Media Reception Notification"
        elseif rtcp_subtype == 0xe then
            ret = "Transmission End Notify"
        elseif rtcp_subtype == 0xf then
            ret = "Transmission Idle"
        end
    elseif rtcp_name == "MCV2" then
        if rtcp_subtype == 0 then
            ret = "Transmission End Request"
        elseif rtcp_subtype == 0x1 then
            ret = "Transmission End Response"
        elseif rtcp_subtype == 0x2 then
            ret = "Media Reception End Request"
        elseif rtcp_subtype == 0x3 then
            ret = "Media Reception End Response"
        elseif rtcp_subtype == 0x4 then
            ret = "Transmission Control Ack"
        end
    end
    return ret
end

function proto_MCVideo.dissector(tvb, pkt_info, tree)
    -- show_support_Dissector()
    local offset = 0
    local date_0 = (tvb(offset, 1)):uint()

    -- 获取消息类型描述
    local rtcp_subtype = bit32.band(date_0, 0xf) -- 位与运算，目前wireshark带的lua 5.2只能这样写
    local rtcp_name = (tvb(8, 4)):string()
    local MCVideoMsgInfo = getMCVideoMsgInfo(rtcp_subtype, rtcp_name)

    local pktlen = tvb:reported_length_remaining()

    -- 普通RTCP消息
    offset = offset + 1
    local rtcp_type = tvb(offset, 1):uint()
    if rtcp_type ~= RTCP_PKT_TYPE_APP_SEPCIFIC then
        return
    end

    local sub_tree = tree:add(proto_MCVideo, tvb:range(RTCP_HEAD_SIZE,pktlen - RTCP_HEAD_SIZE), "Mission Critical Video: Transmission control")
    pkt_info.cols.protocol = "MCVideo"
    pkt_info.cols.info = MCVideoMsgInfo

    local filed_id
    local loop_cnt = 0 -- 防止死循环保护

    -- 开始解码各字段
    offset = RTCP_HEAD_SIZE
    while offset < pktlen and loop_cnt < 255 do
        loop_cnt = loop_cnt + 1
        filed_id = (tvb(offset, 1)):uint()
        print("cur filed_id: " .. filed_id)

        if filed_id == filed_id_table["User ID"] then
            local offset_in = offset
            offset = offset + 1
            local user_id_len = (tvb(offset, 1)):uint()
            offset = offset + 1
            local user_id = (tvb(offset, user_id_len)):string()
            offset = offset + user_id_len
            local padding_len = 0
            if (user_id_len + 2) % 4 ~= 0 then
                padding_len = (4 - (user_id_len + 2) % 4)
                offset = offset + padding_len
            end
            sub_tree:add(mc_fields.UserID, tvb:range(offset_in, user_id_len + padding_len + 2), user_id)
        elseif filed_id == filed_id_table["SSRC"] then
            local offset_in = offset
            offset = offset + 1
            local ssrc_len = (tvb(offset, 1)):uint()
            offset = offset + 1
            local ssrc = tvb:bytes(offset, ssrc_len)
            offset = offset + ssrc_len
            sub_tree:add(mc_fields.SSRC, tvb:range(offset_in, ssrc_len + 2), ssrc:tohex(true, " "))
        elseif filed_id == filed_id_table["Message Sequence Number"] then
            local offset_in = offset
            offset = offset + 1
            local len_value = (tvb(offset, 1)):uint()
            offset = offset + 1
            local msg_seq_num = tvb(offset, len_value):uint()
            offset = offset + len_value
            sub_tree:add(mc_fields.MsgSeqNum, tvb:range(offset_in, len_value + 2), msg_seq_num)
        elseif filed_id == filed_id_table["Transmission Indicator"] then
            local offset_in = offset
            offset = offset + 1
            local len_value = (tvb(offset, 1)):uint()
            offset = offset + 1
            local trans_indi = tvb:bytes(offset, len_value)
            offset = offset + len_value
            sub_tree:add(mc_fields.TransIndi, tvb:range(offset_in, len_value + 2), trans_indi:tohex(true, " "))
        elseif filed_id == filed_id_table["Reject Cause"] then
            local offset_in = offset
            offset = offset + 1
            local len_value = (tvb(offset, 1)):uint()
            offset = offset + 1
            -- reject_cause里必携带2字节的cause_value，可能携带变长的reject phrase。目前我们未实现reject phrase，所以不关注。
            local reject_cause_value = tvb(offset, 2):uint()
            offset = offset + len_value
            sub_tree:add(mc_fields.RejectCause, tvb:range(offset_in, len_value + 2), reject_cause_value)
        elseif filed_id == filed_id_table["Transmission Priority"] then
            local offset_in = offset
            offset = offset + 1
            local len_value = (tvb(offset, 1)):uint()
            if len_value ~= 2 then
                len_value = 2 -- must be 2. 因为目前我们的VMD实现有问题，填了1
            end
            offset = offset + 1
            local trans_priority = tvb(offset, 1):uint()
            offset = offset + len_value
            sub_tree:add(mc_fields.TransPriority, tvb:range(offset_in, len_value + 2), trans_priority)
        elseif filed_id == filed_id_table["Duration"] then
            local offset_in = offset
            offset = offset + 1
            local len_value = (tvb(offset, 1)):uint()
            offset = offset + 1
            local duration = tvb(offset, len_value):uint()
            offset = offset + len_value
            sub_tree:add(mc_fields.Duration, tvb:range(offset_in, len_value + 2), duration)
        elseif filed_id == filed_id_table["Source"] then
            local offset_in = offset
            offset = offset + 1
            local len_value = (tvb(offset, 1)):uint()
            offset = offset + 1
            local source_value = tvb(offset, len_value):uint()
            offset = offset + len_value
            sub_tree:add(mc_fields.Source, tvb:range(offset_in, len_value + 2), source_value)
        elseif filed_id == filed_id_table["Message Name"] then
            local offset_in = offset
            offset = offset + 1
            local len_value = (tvb(offset, 1)):uint()
            offset = offset + 1
            local msg_name = tvb(offset, 4):string()
            offset = offset + len_value
            sub_tree:add(mc_fields.MsgName, tvb:range(offset_in, len_value + 2), msg_name)
        elseif filed_id == filed_id_table["Message Type"] then
            local offset_in = offset
            offset = offset + 1
            local len_value = (tvb(offset, 1)):uint()
            offset = offset + 1
            local msg_type = (tvb(offset, 1)):uint()
            offset = offset + len_value
            sub_tree:add(mc_fields.MsgType, tvb:range(offset_in, len_value + 2), msg_type)
        elseif filed_id == filed_id_table["Reception Priority"] then
            local offset_in = offset
            offset = offset + 1
            local len_value = (tvb(offset, 1)):uint()
            offset = offset + 1
            local RecepPriority = (tvb(offset, 1)):uint()
            offset = offset + len_value
            sub_tree:add(mc_fields.RecepPriority, tvb:range(offset_in, len_value + 2), RecepPriority)
        elseif filed_id == filed_id_table["Result"] then
            local offset_in = offset
            offset = offset + 1
            local len_value = (tvb(offset, 1)):uint()
            offset = offset + 1
            local result_value = (tvb(offset, 2)):uint()
            offset = offset + len_value
            sub_tree:add(mc_fields.Result, tvb:range(offset_in, len_value + 2), result_value)
        else
            print("unkown field id:" .. filed_id)
            break
        end
    end

    return true
end

DissectorTable.get("rtcp.app.name"):add("MCV0", proto_MCVideo)
DissectorTable.get("rtcp.app.name"):add("MCV1", proto_MCVideo)
DissectorTable.get("rtcp.app.name"):add("MCV2", proto_MCVideo)
