use anyhow::{ensure, Result};
use std::path::Path;

pub struct EspImageBuilder {
    size_mb: u32,
}

/// Geometry facts about a built bootable FAT16 ESP.
#[derive(Debug, Clone, Copy)]
pub struct EspGeometry {
    pub total_sectors: u32,
    pub sectors_per_cluster: u32,
    pub fat_sectors: u32,
    pub cluster_count: u32,
    pub first_data_sector: u32,
    /// First cluster holding the payload file content.
    pub payload_first_cluster: u32,
    pub payload_clusters: u32,
}

/// FAT directory entry attributes.
const ATTR_DIRECTORY: u8 = 0x10;

/// FAT16 geometry constants (kept module-level so tests can verify layout).
pub const RESERVED_SECTORS: u32 = 1;
pub const NUM_FATS: u32 = 2;
pub const ROOT_ENTRIES: u32 = 256; // 16 sectors of 16 entries

/// Fixed timestamp for directory entries (2026-01-01 00:00:00) so builds
/// are byte-reproducible.
const DIR_DATE: u16 = ((2026 - 1980) << 9) | (1 << 5) | 1; // 0x5C21
const DIR_TIME: u16 = 0;

impl EspImageBuilder {
    pub fn new(size_mb: u32) -> Self {
        Self { size_mb }
    }

    pub fn build_with_payload(&self, payload: &[u8], output: &Path) -> Result<()> {
        // FAT12/16 ESP image with payload embedded as EFI binary
        // Minimal FAT structure: BPB + FAT + root dir + payload
        let sector_size: u32 = 512;
        let total_sectors = self.size_mb * 1024 * 1024 / sector_size;
        let mut image = vec![0u8; (total_sectors * sector_size) as usize];

        // Boot sector / BPB
        image[0] = 0xEB; // JMP short
        image[1] = 0x3C;
        image[2] = 0x90; // NOP
        image[3..11].copy_from_slice(b"BARZAKH ");

        // Bytes per sector
        image[11] = (sector_size & 0xFF) as u8;
        image[12] = (sector_size >> 8) as u8;

        // Sectors per cluster
        image[13] = 0x08;

        // Reserved sectors
        image[14] = 0x20;
        image[15] = 0x00;

        // Number of FATs
        image[16] = 0x02;

        // Total sectors 16-bit (0 = use 32-bit field)
        image[19] = 0x00;
        image[20] = 0x00;

        // Media type (fixed disk)
        image[21] = 0xF8;

        // Total sectors 32-bit
        let ts_bytes = total_sectors.to_le_bytes();
        image[32..36].copy_from_slice(&ts_bytes);

        // Signature
        image[510] = 0x55;
        image[511] = 0xAA;

        // Write payload into the data region
        let data_start = 0x20 * sector_size as usize;
        if data_start + payload.len() < image.len() {
            image[data_start..data_start + payload.len()].copy_from_slice(payload);
        }

        std::fs::write(output, &image)?;
        Ok(())
    }

    /// Build a **real FAT16** ESP that OVMF can boot, with the payload
    /// stored as `\EFI\BOOT\BOOTX64.EFI` (the removable-media boot path).
    ///
    /// Unlike [`EspImageBuilder::build_with_payload`] (a synthetic image
    /// meant for scanner corpora), this produces a spec-conformant
    /// filesystem: BPB, two FATs, a root directory, `\EFI` and
    /// `\EFI\BOOT` subdirectories with `.`/`..` entries, and the payload's
    /// cluster chain — enough for EDK II FatPkg to enumerate and the
    /// firmware boot manager to launch.
    pub fn build_bootable(&self, payload: &[u8], output: &Path) -> Result<EspGeometry> {
        const SECTOR: u32 = 512;
        // FAT16 requires >= 4085 clusters (below that the on-disk format
        // degrades to FAT12 with 12-bit entries). Pick a cluster size that
        // keeps the cluster count in FAT16 range.
        ensure!(self.size_mb >= 4, "bootable ESP needs >= 4 MB");
        let total_sectors = self.size_mb * 1024 * 1024 / SECTOR;
        let mut sectors_per_cluster = 0u32;
        let mut fat_sectors = 0u32;
        let mut cluster_count = 0u32;
        for &spc in &[8u32, 4, 2, 1] {
            let mut f = 64u32; // initial guess, iterate to fixed point
            for _ in 0..8 {
                let data_sectors =
                    total_sectors - RESERVED_SECTORS - NUM_FATS * f - ROOT_ENTRIES / 16;
                let c = data_sectors / spc;
                let f_next = ((c + 2) * 2).div_ceil(SECTOR);
                if f_next == f {
                    break;
                }
                f = f_next;
            }
            let data_sectors = total_sectors - RESERVED_SECTORS - NUM_FATS * f - ROOT_ENTRIES / 16;
            let c = data_sectors / spc;
            if c >= 4085 {
                sectors_per_cluster = spc;
                fat_sectors = f;
                cluster_count = c;
                break;
            }
        }
        ensure!(
            sectors_per_cluster > 0,
            "image too small for a FAT16 filesystem (need >= 4 MB)"
        );

        let cluster_size = (sectors_per_cluster * SECTOR) as usize;
        let root_dir_lba = RESERVED_SECTORS + NUM_FATS * fat_sectors;
        let first_data_sector = root_dir_lba + ROOT_ENTRIES / 16;

        // Cluster allocation: 2 = \EFI, 3 = \EFI\BOOT, 4.. = payload.
        let payload_clusters = payload.len().div_ceil(cluster_size) as u32;
        ensure!(
            payload_clusters > 0 && payload_clusters + 4 <= cluster_count,
            "payload ({} bytes) does not fit in the ESP",
            payload.len()
        );
        let payload_first_cluster = 4u32;

        let mut image = vec![0u8; (total_sectors * SECTOR) as usize];
        Self::write_boot_sector(
            &mut image,
            total_sectors,
            sectors_per_cluster,
            fat_sectors,
            ROOT_ENTRIES,
            RESERVED_SECTORS,
            NUM_FATS,
        );
        Self::write_fats(
            &mut image,
            fat_sectors,
            NUM_FATS,
            payload_first_cluster,
            payload_clusters,
        );
        Self::write_root_dir(&mut image, root_dir_lba);
        let data = &mut image[(first_data_sector * SECTOR) as usize..];
        // Cluster 2: \EFI directory — ". ", ".. ", "BOOT".
        {
            let dir = &mut data[..cluster_size];
            Self::write_dir_entry(&mut dir[0..32], ".          ", ATTR_DIRECTORY, 2, 0);
            Self::write_dir_entry(&mut dir[32..64], "..         ", ATTR_DIRECTORY, 0, 0);
            Self::write_dir_entry(&mut dir[64..96], "BOOT       ", ATTR_DIRECTORY, 3, 0);
        }
        // Cluster 3: \EFI\BOOT directory — ". ", ".. ", "BOOTX64 EFI".
        {
            let dir = &mut data[cluster_size..2 * cluster_size];
            Self::write_dir_entry(&mut dir[0..32], ".          ", ATTR_DIRECTORY, 3, 0);
            Self::write_dir_entry(&mut dir[32..64], "..         ", ATTR_DIRECTORY, 2, 0);
            Self::write_dir_entry(
                &mut dir[64..96],
                "BOOTX64 EFI",
                0,
                payload_first_cluster,
                payload.len() as u32,
            );
        }
        // Payload content across its cluster chain.
        let file_region = &mut data[(((payload_first_cluster - 2) as usize) * cluster_size)..];
        file_region[..payload.len()].copy_from_slice(payload);

        std::fs::write(output, &image)?;
        Ok(EspGeometry {
            total_sectors,
            sectors_per_cluster,
            fat_sectors,
            cluster_count,
            first_data_sector,
            payload_first_cluster,
            payload_clusters,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn write_boot_sector(
        image: &mut [u8],
        total_sectors: u32,
        sectors_per_cluster: u32,
        fat_sectors: u32,
        root_entries: u32,
        reserved: u32,
        num_fats: u32,
    ) {
        let bs = &mut image[..512];
        bs[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]); // jmp short + nop
        bs[3..11].copy_from_slice(b"BARZAKH ");
        bs[11..13].copy_from_slice(&512u16.to_le_bytes());
        bs[13] = sectors_per_cluster as u8;
        bs[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
        bs[16] = num_fats as u8;
        bs[17..19].copy_from_slice(&(root_entries as u16).to_le_bytes());
        bs[19..21].copy_from_slice(&0u16.to_le_bytes()); // total16: use total32
        bs[21] = 0xF8; // media: fixed disk
        bs[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
        bs[24..26].copy_from_slice(&63u16.to_le_bytes()); // sectors/track
        bs[26..28].copy_from_slice(&255u16.to_le_bytes()); // heads
        bs[28..32].copy_from_slice(&0u32.to_le_bytes()); // hidden
        bs[32..36].copy_from_slice(&total_sectors.to_le_bytes());
        bs[36] = 0x80; // BIOS drive
        bs[38] = 0x29; // extended boot signature
        bs[39..43].copy_from_slice(&0x42_5A_4B_48u32.to_le_bytes()); // "BZKH"
        bs[43..54].copy_from_slice(b"BARZAKHBOOT"); // 11 bytes
        bs[54..62].copy_from_slice(b"FAT16   ");
        bs[510] = 0x55;
        bs[511] = 0xAA;
    }

    #[allow(clippy::too_many_arguments)]
    fn write_fats(
        image: &mut [u8],
        fat_sectors: u32,
        num_fats: u32,
        payload_first_cluster: u32,
        payload_clusters: u32,
    ) {
        let fat_len = (fat_sectors * 512) as usize;
        let mut fat = vec![0u8; fat_len];
        // Reserved entries.
        fat[0..2].copy_from_slice(&0xFFF8u16.to_le_bytes());
        fat[2..4].copy_from_slice(&0xFFFFu16.to_le_bytes());
        // Cluster 2 (\EFI) and 3 (\EFI\BOOT): single-cluster directories.
        let set = |fat: &mut [u8], cluster: u32, value: u16| {
            let off = (cluster * 2) as usize;
            fat[off..off + 2].copy_from_slice(&value.to_le_bytes());
        };
        set(&mut fat, 2, 0xFFFF);
        set(&mut fat, 3, 0xFFFF);
        // Payload chain.
        for i in 0..payload_clusters {
            let cluster = payload_first_cluster + i;
            let value = if i + 1 == payload_clusters {
                0xFFFF
            } else {
                (cluster + 1) as u16
            };
            set(&mut fat, cluster, value);
        }
        // Mirror the FAT.
        for i in 0..num_fats {
            let off = ((1 + i * fat_sectors) * 512) as usize;
            image[off..off + fat_len].copy_from_slice(&fat);
        }
    }

    fn write_root_dir(image: &mut [u8], root_dir_lba: u32) {
        let off = (root_dir_lba * 512) as usize;
        Self::write_dir_entry(
            &mut image[off..off + 32],
            "EFI        ",
            ATTR_DIRECTORY,
            2,
            0,
        );
    }

    /// Write a 32-byte FAT directory entry.
    fn write_dir_entry(entry: &mut [u8], name: &str, attr: u8, first_cluster: u32, size: u32) {
        debug_assert_eq!(entry.len(), 32);
        entry[..11].copy_from_slice(name.as_bytes());
        entry[11] = attr;
        entry[22..24].copy_from_slice(&DIR_TIME.to_le_bytes()); // write time
        entry[24..26].copy_from_slice(&DIR_DATE.to_le_bytes()); // write date
        entry[20..22].copy_from_slice(&0u16.to_le_bytes()); // first cluster high
        entry[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes()); // low
        entry[28..32].copy_from_slice(&size.to_le_bytes()); // file size (u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootable_esp_has_valid_fat16_geometry() {
        let payload = vec![0x90u8; 8192]; // 2 clusters at 4 KiB
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("esp.img");
        let geo = EspImageBuilder::new(16)
            .build_bootable(&payload, &out)
            .unwrap();
        // FAT16 range: 4085..=65524 clusters.
        assert!(
            geo.cluster_count >= 4085,
            "cluster count {} must be FAT16",
            geo.cluster_count
        );
        assert_eq!(geo.payload_first_cluster, 4);
        assert_eq!(geo.payload_clusters, 2);
        let image = std::fs::read(&out).unwrap();
        // Boot sector sanity.
        assert_eq!(&image[54..62], b"FAT16   ");
        assert_eq!(image[510], 0x55);
        assert_eq!(image[511], 0xAA);
        assert_eq!(u16::from_le_bytes(image[11..13].try_into().unwrap()), 512);
        // Root directory: \EFI entry pointing at cluster 2.
        let root_off = ((RESERVED_SECTORS + 2 * geo.fat_sectors) as usize) * 512;
        let e = &image[root_off..root_off + 32];
        assert_eq!(&e[..11], b"EFI        ");
        assert_eq!(e[11], ATTR_DIRECTORY);
        assert_eq!(
            u16::from_le_bytes(e[26..28].try_into().unwrap()),
            2,
            "\\EFI must point at cluster 2"
        );
        // Payload content present at cluster 4.
        let data_off = (geo.first_data_sector as usize) * 512;
        let file_off = data_off
            + ((geo.payload_first_cluster - 2) as usize) * (geo.sectors_per_cluster as usize) * 512;
        assert_eq!(&image[file_off..file_off + 16], &[0x90u8; 16]);
        // FAT chain: first payload cluster links to 5, second is EOC.
        let fat = &image[512..];
        let c4 = u16::from_le_bytes(fat[8..10].try_into().unwrap());
        let c5 = u16::from_le_bytes(fat[10..12].try_into().unwrap());
        assert_eq!(c4, 5);
        assert_eq!(c5, 0xFFFF);
    }

    #[test]
    fn bootable_esp_rejects_tiny_images() {
        let err = EspImageBuilder::new(1)
            .build_bootable(b"payload", Path::new("/tmp/nope.img"))
            .unwrap_err();
        assert!(err.to_string().contains("4 MB"));
    }

    #[test]
    fn synthetic_esp_still_builds() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("synthetic.img");
        EspImageBuilder::new(4)
            .build_with_payload(b"DATA", &out)
            .unwrap();
        let image = std::fs::read(&out).unwrap();
        assert_eq!(&image[3..11], b"BARZAKH ");
    }
}
