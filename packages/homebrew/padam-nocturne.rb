class PadamNocturne < Formula
  include Language::Python::Virtualenv

  desc "Local-first AI memory MCP server with injection firewall, DLP shield, and X-Wing PQC"
  homepage "https://github.com/MaksimGalatin/padam-nocturne"
  url "https://github.com/MaksimGalatin/padam-nocturne/archive/refs/tags/v0.8.0.tar.gz"
  sha256 "d9f1a44c4da93ca8f92f1939f3fc953497578211a05a8cdc40d2c01763a74562"
  license :cannot_represent

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "0.8.0", shell_output("#{bin}/padam --version")
  end
end
