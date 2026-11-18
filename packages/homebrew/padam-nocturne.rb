class PadamNocturne < Formula
  include Language::Python::Virtualenv

  desc "Local-first AI memory MCP server with injection firewall, DLP shield, and X-Wing PQC"
  homepage "https://github.com/MaksimGalatin/padam-nocturne"
  url "https://github.com/MaksimGalatin/padam-nocturne/archive/refs/tags/v0.6.4.tar.gz"
  license "AGPL-3.0-only"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "0.6.4", shell_output("#{bin}/padam --version")
  end
end
