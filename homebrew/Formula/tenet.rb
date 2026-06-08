# Homebrew formula for the tenet CLI (non-cask / command-line only).
#
# Installs the prebuilt single-file binary from GitHub Releases.
#
# Quick demo install (no tap needed):
#   brew install --formula https://raw.githubusercontent.com/maceip/tenet/master/homebrew/Formula/tenet.rb
#
# Or set up a tap for `brew install tenet`:
#   brew tap maceip/tenet https://github.com/maceip/tenet
#   brew install tenet
#
# Supported (from the build-binaries workflow):
#   macOS arm64 (Apple Silicon), macOS x86_64 (Intel), Linux x86_64, Windows (direct .exe)

class Tenet < Formula
  desc "Privacy-preserving expert mixnet client (ask + sponsor payments rail)"
  homepage "https://github.com/maceip/tenet"
  license "BSD-2-Clause"

  version "latest"

  on_macos do
    on_arm do
      url "https://github.com/maceip/tenet/releases/latest/download/tenet-macos-arm64"
      sha256 :no_check
    end
    on_intel do
      url "https://github.com/maceip/tenet/releases/latest/download/tenet-macos-x86_64"
      sha256 :no_check
    end
  end

  on_linux do
    url "https://github.com/maceip/tenet/releases/latest/download/tenet-linux-x86_64"
    sha256 :no_check
  end

  def install
    bin.install Dir["tenet-*"].first => "tenet"
    chmod 0755, bin/"tenet"
  end

  def caveats
    <<~EOS
      The tenet CLI is now on your PATH.

      Quick smoke:
        tenet --help
        tenet ask --help

      Full demo from a git checkout:
        git clone https://github.com/maceip/tenet.git ~/tenet
        cd ~/tenet && ./scripts/demo/run-safe.sh
    EOS
  end

  test do
    assert_match "tenet", shell_output("#{bin}/tenet --help")
  end
end
