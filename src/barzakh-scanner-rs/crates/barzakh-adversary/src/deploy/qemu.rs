use std::path::Path;

use anyhow::Result;

use crate::Arch;

pub struct QemuConfig {
    pub arch: Arch,
    pub memory_mb: u32,
    pub firmware_path: Option<String>,
    pub timeout_secs: u32,
}

impl Default for QemuConfig {
    fn default() -> Self {
        Self {
            arch: Arch::X86_64,
            memory_mb: 256,
            firmware_path: None,
            timeout_secs: 30,
        }
    }
}

impl QemuConfig {
    pub fn binary_name(&self) -> &str {
        match self.arch {
            Arch::X86_64 => "qemu-system-x86_64",
            Arch::Aarch64 => "qemu-system-aarch64",
            Arch::RiscV64 => "qemu-system-riscv64",
            Arch::Power64 => "qemu-system-ppc64",
            Arch::Armv7 => "qemu-system-arm",
        }
    }

    pub fn build_args(&self, esp_image: &Path) -> Vec<String> {
        let mut args = vec![
            "-nographic".to_string(),
            "-m".to_string(),
            format!("{}M", self.memory_mb),
            "-no-reboot".to_string(),
        ];

        match self.arch {
            Arch::X86_64 => {
                if let Some(ref fw) = self.firmware_path {
                    args.extend([
                        "-drive".to_string(),
                        format!("if=pflash,format=raw,readonly=on,file={}", fw),
                    ]);
                }
                args.extend([
                    "-drive".to_string(),
                    format!("format=raw,file={}", esp_image.to_string_lossy()),
                ]);
            }
            Arch::Aarch64 => {
                args.extend(["-machine".to_string(), "virt".to_string()]);
                args.extend(["-cpu".to_string(), "cortex-a72".to_string()]);
                if let Some(ref fw) = self.firmware_path {
                    args.extend([
                        "-drive".to_string(),
                        format!("if=pflash,format=raw,readonly=on,file={}", fw),
                    ]);
                }
                args.extend([
                    "-drive".to_string(),
                    format!("format=raw,file={}", esp_image.to_string_lossy()),
                ]);
            }
            Arch::RiscV64 => {
                args.extend(["-machine".to_string(), "virt".to_string()]);
                args.extend(["-cpu".to_string(), "rv64".to_string()]);
                args.extend(["-bios".to_string(), "none".to_string()]);
                if let Some(ref fw) = self.firmware_path {
                    args.extend([
                        "-drive".to_string(),
                        format!("if=pflash,format=raw,readonly=on,file={}", fw),
                    ]);
                }
                args.extend([
                    "-drive".to_string(),
                    format!("format=raw,file={}", esp_image.to_string_lossy()),
                ]);
            }
            Arch::Power64 => {
                args.extend(["-machine".to_string(), "powernv".to_string()]);
                if let Some(ref fw) = self.firmware_path {
                    args.extend([
                        "-drive".to_string(),
                        format!("if=pflash,format=raw,readonly=on,file={}", fw),
                    ]);
                }
                args.extend([
                    "-drive".to_string(),
                    format!("format=raw,file={}", esp_image.to_string_lossy()),
                ]);
            }
            Arch::Armv7 => {
                args.extend(["-machine".to_string(), "virt".to_string()]);
                args.extend(["-cpu".to_string(), "cortex-a15".to_string()]);
                if let Some(ref fw) = self.firmware_path {
                    args.extend([
                        "-drive".to_string(),
                        format!("if=pflash,format=raw,readonly=on,file={}", fw),
                    ]);
                }
                args.extend([
                    "-drive".to_string(),
                    format!("format=raw,file={}", esp_image.to_string_lossy()),
                ]);
            }
        }

        args
    }
}

pub fn dump_memory(_qemu_config: &QemuConfig, _output: &Path) -> Result<()> {
    // Future: connect via QMP, issue pmemsave, collect dump
    // For now, payload generation + direct scanning is the primary path
    anyhow::bail!("QEMU memory dump requires running QEMU instance — use generate + scan directly")
}
