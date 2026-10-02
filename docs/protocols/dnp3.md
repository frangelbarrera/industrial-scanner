# DNP3

DNP3 (Distributed Network Protocol 3) is the IEEE 1815-2012 standard for
SCADA communication, widely used in electric utilities and water/wastewater.
It runs over TCP/UDP port 20000.

## What IndustrialScanner does

The DNP3 analyzer:

1. Reads PCAP files
2. Filters TCP/UDP traffic on port 20000
3. Locates DNP3 frames by magic bytes (0x05 0x64)
4. Parses the link layer (10 bytes: sync, length, control, dest, src, CRC)
5. Parses the transport layer (1 byte)
6. Parses the application layer (function code at offset 12)
7. Classifies each packet by function code
8. Flags suspect functions (Operate, Write, ColdRestart, WarmRestart,
   DeleteFile, StopApplication, etc.)
9. Enriches with MITRE ATT&CK for ICS techniques

## Function codes detected

| Code | Name | Suspect | Description |
|---|---|---|---|
| 0x00 | Confirm | No | Acknowledgement |
| 0x01 | Read | No | Read data |
| 0x02 | Write | Yes | Write data |
| 0x03 | Select | Yes | Pre-select for operate |
| 0x04 | Operate | Yes | Operate control point |
| 0x05 | DirectOperate | Yes | Direct operate (no select) |
| 0x06 | DirectOperateNoAck | Yes | Direct operate without ack |
| 0x0D | ColdRestart | Yes | Cold restart RTU |
| 0x0E | WarmRestart | Yes | Warm restart RTU |
| 0x12 | StopApplication | Yes | Stop application |
| 0x14 | EnableUnsolicited | Yes | Enable unsolicited responses |
| 0x15 | DisableUnsolicited | Yes | Disable unsolicited responses |
| 0x16 | AssignClass | Yes | Assign class to objects |
| 0x19 | OpenFile | No | Open file on RTU |
| 0x1A | CloseFile | No | Close file |
| 0x1B | DeleteFile | Yes | Delete file on RTU |
| 0x1D | Authenticate | Yes | Authentication (SA v5) |
| 0x81 | Response | No | Response to request |
| 0x82 | UnsolicitedResponse | No | Unsolicited response |

## Usage

```bash
# Analyze a single PCAP
industrial-scanner dnp3 --pcap capture.pcap

# Batch process all PCAPs in pcaps/dnp3/
python run_dnp3_all.py
```

## Output

- **JSON report** in `reports/dnp3_batch/<basename>.json`
- **HTML report** in `reports/dnp3_batch/<basename>.html`

Each packet entry includes:

- src, dst, function, length, hints
- suspect (boolean)
- mitre_attack (list of MITRE techniques)

## Limitations

- The parser does not yet decode the **object headers** within the data
  block (only the function code is extracted). For full object-level
  analysis, use the `dnp3-python` library from Step Function I/O.
- **DNP3 Secure Authentication v5 (SA v5)** is detected (function 0x1D)
  but the SA v5 challenge-response is not validated. Whether SA v5 or
  another compensating control is required depends on the applicable
  deployment profile, asset-owner requirements, risk assessment, and
  target security level; IEC 62443 does not impose a universal
  protocol-version mandate.

## Security considerations

- DNP3 has **no authentication by default**. Anyone with network access
  to TCP/20000 can issue Operate, Write, ColdRestart.
- For production, use authenticated DNP3 where supported and evaluate
  **DNP3 SA v5** against the applicable deployment profile, asset-owner
  requirements, risk assessment, and target security level.
- Restrict TCP/20000 access via firewall rules to known master/RTU pairs
- Use TLS (DNP3 over TLS) for additional confidentiality
