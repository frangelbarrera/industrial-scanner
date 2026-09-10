"""
Strict DNP3 application-layer parser.

Decodes DNP3 frames per IEEE 1815-2012. The parser identifies the link,
transport, and application layer function codes by binary offset rather
than ASCII substring matching, which produces reliable classifications.

Reference: IEEE 1815-2012, Wireshark packet-dnp.c.
"""

from __future__ import annotations

from typing import Any

from scapy.all import Raw

# ---------------------------------------------------------------------------
# DNP3 link-layer constants
# ---------------------------------------------------------------------------
DNP3_SYNC_0 = 0x05
DNP3_SYNC_1 = 0x64  # Master/outstation link frame
DNP3_SYNC_1_RTU = 0xC4  # RTU back-to-back frame (rare)

# Link function codes (LCB byte 1, lower 4 bits)
LINK_FUNC_RESET_LINK = 0x0
LINK_FUNC_RESET_USER = 0x2
LINK_FUNC_TEST_LINK = 0x3
LINK_FUNC_USER_DATA = 0x4
LINK_FUNC_NOT_SUPPORTED = 0x9
LINK_FUNC_REQUEST_STATUS = 0xA
LINK_FUNC_NOT_USED = 0xB

LINK_FUNC_NAMES = {
    0x0: "ResetLinkStates",
    0x2: "ResetUser",
    0x3: "TestLinkStates",
    0x4: "UserData",
    0x9: "NotSupported",
    0xA: "RequestLinkStatus",
    0xB: "NotUsed",
}

# ---------------------------------------------------------------------------
# DNP3 application-layer function codes (AC byte, byte 1 of the app header)
# Per IEEE 1815-2012 §5.1.5.1 and Wireshark packet-dnp.c
# ---------------------------------------------------------------------------
APP_FUNC_CONFIRM = 0x00
APP_FUNC_READ = 0x01
APP_FUNC_WRITE = 0x02
APP_FUNC_SELECT = 0x03
APP_FUNC_OPERATE = 0x04
APP_FUNC_DIRECT_OPERATE = 0x05
APP_FUNC_DIRECT_OPERATE_NO_ACK = 0x06
APP_FUNC_IMMEDIATE_FREEZE = 0x07
APP_FUNC_IMMEDIATE_FREEZE_NO_ACK = 0x08
APP_FUNC_FREEZE_CLEAR = 0x09
APP_FUNC_FREEZE_CLEAR_NO_ACK = 0x0A
APP_FUNC_FREEZE_AT_TIME = 0x0B
APP_FUNC_FREEZE_AT_TIME_NO_ACK = 0x0C
APP_FUNC_COLD_RESTART = 0x0D
APP_FUNC_WARM_RESTART = 0x0E
APP_FUNC_INITIALIZE_DATA = 0x0F
APP_FUNC_INITIALIZE_APPLICATION = 0x10
APP_FUNC_START_APPLICATION = 0x11
APP_FUNC_STOP_APPLICATION = 0x12
APP_FUNC_SAVE_CONFIG = 0x13
APP_FUNC_ENABLE_UNSOLICITED = 0x14
APP_FUNC_DISABLE_UNSOLICITED = 0x15
APP_FUNC_ASSIGN_CLASS = 0x16
APP_FUNC_DELAY_MEASURE = 0x17
APP_FUNC_RECORD_CURRENT_TIME = 0x18
APP_FUNC_OPEN_FILE = 0x19
APP_FUNC_CLOSE_FILE = 0x1A
APP_FUNC_DELETE_FILE = 0x1B
APP_FUNC_GET_FILE_INFO = 0x1C
APP_FUNC_AUTHENTICATE = 0x1D
APP_FUNC_ABORT = 0x1E
APP_FUNC_RESPONSE = 0x81
APP_FUNC_UNSOLICITED_RESPONSE = 0x82

APP_FUNC_NAMES = {
    0x00: "Confirm",
    0x01: "Read",
    0x02: "Write",
    0x03: "Select",
    0x04: "Operate",
    0x05: "DirectOperate",
    0x06: "DirectOperateNoAck",
    0x07: "ImmediateFreeze",
    0x08: "ImmediateFreezeNoAck",
    0x09: "FreezeClear",
    0x0A: "FreezeClearNoAck",
    0x0B: "FreezeAtTime",
    0x0C: "FreezeAtTimeNoAck",
    0x0D: "ColdRestart",
    0x0E: "WarmRestart",
    0x0F: "InitializeData",
    0x10: "InitializeApplication",
    0x11: "StartApplication",
    0x12: "StopApplication",
    0x13: "SaveConfig",
    0x14: "EnableUnsolicited",
    0x15: "DisableUnsolicited",
    0x16: "AssignClass",
    0x17: "DelayMeasure",
    0x18: "RecordCurrentTime",
    0x19: "OpenFile",
    0x1A: "CloseFile",
    0x1B: "DeleteFile",
    0x1C: "GetFileInfo",
    0x1D: "Authenticate",
    0x1E: "Abort",
    0x81: "Response",
    0x82: "UnsolicitedResponse",
}

# Function codes that represent control or state-changing operations.
SUSPECT_FUNCS = {
    "Operate",
    "DirectOperate",
    "DirectOperateNoAck",
    "Write",
    "Select",  # precursor to Operate
    "ColdRestart",
    "WarmRestart",
    "StopApplication",
    "DeleteFile",
    "EnableUnsolicited",
    "DisableUnsolicited",
    "InitializeData",
    "InitializeApplication",
    "SaveConfig",
    "AssignClass",
}

# Hints are now informational only (presence of certain ASCII strings in
# the payload, useful for human reviewers but not used for classification).
HINTS = [b"UNSOL", b"OPER", b"RESTART", b"SELECT", b"READ", b"WRITE", b"DNP"]


def _find_dnp3_payload(payload: bytes) -> bytes | None:
    """Locate the start of a DNP3 frame within a raw payload.

    DNP3 link frames begin with the magic bytes 0x05 0x64 (or 0x05 0xC4
    for RTU back-to-back). Some captures include non-DNP3 padding before
    the magic, so we scan for it.
    """
    if len(payload) < 10:
        return None
    for i in range(min(len(payload) - 10, 64) + 1):
        if payload[i] == DNP3_SYNC_0 and payload[i + 1] in (DNP3_SYNC_1, DNP3_SYNC_1_RTU):
            return payload[i:]
    return None


def _parse_link_layer(frame: bytes) -> dict[str, int] | None:
    """Parse the DNP3 link layer (10 bytes).

    Layout:
        byte 0: SYNC 0 (0x05)
        byte 1: SYNC 1 (0x64)
        byte 2: length (5-255, total bytes that follow including CRC)
        byte 3: control byte (DIR, PRM, FCB, FCV, function code)
        bytes 4-9: destination (16-bit LE) + source (16-bit LE)
    """
    if len(frame) < 10:
        return None
    if frame[0] != DNP3_SYNC_0 or frame[1] not in (DNP3_SYNC_1, DNP3_SYNC_1_RTU):
        return None
    ctrl = frame[3]
    return {
        "sync0": frame[0],
        "sync1": frame[1],
        "length": frame[2],
        "dir": (ctrl >> 7) & 0x1,
        "prm": (ctrl >> 6) & 0x1,
        "fcb": (ctrl >> 5) & 0x1,
        "fcv": (ctrl >> 4) & 0x1,
        "link_func": ctrl & 0x0F,
        "dest": int.from_bytes(frame[4:6], "little"),
        "src": int.from_bytes(frame[6:8], "little"),
    }


def _parse_app_layer(frame: bytes, link: dict[str, int]) -> dict[str, int] | None:
    """Parse the DNP3 application layer (follows the 10-byte link header +
    optional transport byte).

    The transport header is 1 byte if the frame has User Data (link func 4).
    The application header is at least 2 bytes: byte 0 = control, byte 1 =
    function code.
    """
    if link["link_func"] != LINK_FUNC_USER_DATA:
        return None
    # Transport byte is at offset 10; application header starts at offset 11.
    app_ctrl_offset = 10 + 1
    if len(frame) < app_ctrl_offset + 2:
        return None
    app_ctrl = frame[app_ctrl_offset]
    app_func = frame[app_ctrl_offset + 1]
    return {
        "app_ctrl": app_ctrl,
        "app_func": app_func,
        "fir": (app_ctrl >> 7) & 0x1,
        "fin": (app_ctrl >> 6) & 0x1,
        "seq": (app_ctrl >> 0) & 0x3F,
    }


def _classify_app_function(payload: bytes) -> str:
    """Classify a DNP3 payload into an application-layer function name.

    Strict implementation: parses the link layer, transport, and application
    layer per IEEE 1815-2012. Returns 'NonDNP3' if the payload does not
    contain a parseable DNP3 frame, 'UnknownDNP3' if the frame is DNP3
    but the function code is not in our table.
    """
    frame = _find_dnp3_payload(payload)
    if frame is None:
        return "NonDNP3"
    link = _parse_link_layer(frame)
    if link is None:
        return "NonDNP3"
    # The length field counts bytes after the length octet. Reject truncated
    # frames before interpreting application bytes; extra TCP payload is
    # tolerated because captures may contain padding or concatenated data.
    if len(frame) < 3 + link["length"]:
        return "UnknownDNP3"
    if link["link_func"] != LINK_FUNC_USER_DATA:
        return LINK_FUNC_NAMES.get(link["link_func"], "UnknownDNP3")
    app = _parse_app_layer(frame, link)
    if app is None:
        return "UnknownDNP3"
    return APP_FUNC_NAMES.get(app["app_func"], "UnknownDNP3")


def parse_dnp3_packet(pkt: Any) -> dict[str, Any] | None:
    """Extract useful metadata from a DNP3 packet."""
    if Raw not in pkt:
        return None
    payload = bytes(pkt[Raw])
    src = getattr(pkt[0][1], "src", None)
    dst = getattr(pkt[0][1], "dst", None)

    func = _classify_app_function(payload)

    hints: list[str] = []
    for h in HINTS:
        if h in payload:
            hints.append(h.decode("latin-1", errors="ignore"))

    return {
        "src": src or "unknown",
        "dst": dst or "unknown",
        "function": func,
        "length": len(payload),
        "hints": hints,
        "suspect": func in SUSPECT_FUNCS,
    }
