class Barzakh < Formula
  desc "UEFI firmware security research platform: scanner, adversary, server, and agent"
  homepage "https://github.com/yasindce1998/Barzakh"
  url "https://github.com/yasindce1998/Barzakh/archive/refs/tags/v0.5.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000" # TODO: set on release
  license "BSD-2-Clause-Patent"

  # The scanner runs on macOS for offline analysis of firmware images
  # (HPC/JTAG/HIL features require Linux hardware access).
  depends_on "rust" => :build

  def install
    # Workspace layout: the Rust workspace lives under src/barzakh-scanner-rs
    #   crates/barzakh-cli     -> bins: barzakh-scanner, barzakh-adversary
    #   crates/barzakh-server  -> bin:  barzakh-server
    #   crates/barzakh-agent   -> bin:  barzakh-agent
    workspace = buildpath/"src/barzakh-scanner-rs"

    # Install the CLI binaries (scanner + adversary) from the barzakh-cli crate
    system "cargo", "install", "--locked", "--path", workspace/"crates/barzakh-cli",
           "--root", prefix
    # Install the dashboard/API server binary
    system "cargo", "install", "--locked", "--path", workspace/"crates/barzakh-server",
           "--root", prefix
    # Install the real-time monitoring agent binary
    system "cargo", "install", "--locked", "--path", workspace/"crates/barzakh-agent",
           "--root", prefix
  end

  def caveats
    <<~EOS
      Hardware-dependent detectors (hpc_monitor, debug_interface, HIL lab
      tooling) require Linux with the appropriate access. On macOS the
      scanner provides offline static analysis of firmware images.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/barzakh-scanner --version")
    assert_match version.to_s, shell_output("#{bin}/barzakh-adversary --version")
    assert_match version.to_s, shell_output("#{bin}/barzakh-server --version")
    assert_match version.to_s, shell_output("#{bin}/barzakh-agent --version")
    system "#{bin}/barzakh-scanner", "--version"
  end
end
