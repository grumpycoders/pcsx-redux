class MipselNoneElfBinutils < Formula
  desc "FSF Binutils for mipsel cross development"
  homepage "https://www.gnu.org/software/binutils/"
  url "https://ftpmirror.gnu.org/gnu/binutils/binutils-2.45.tar.gz"
  mirror "https://mirrors.kernel.org/gnu/binutils/binutils-2.45.tar.gz"
  sha256 "8a3eb4b10e7053312790f21ee1a38f7e2bbd6f4096abb590d3429e5119592d96"

  depends_on "texinfo" => :build

  def install
    system "./configure", "--target=mipsel-none-elf",
                          "--disable-multilib",
                          "--disable-nls",
                          "--disable-werror",
                          "--prefix=#{prefix}"
    system "make"
    system "make", "install-strip"
  end
  test do
    assert_match "f()", shell_output("#{bin}/mipsel-none-elf-c++filt _Z1fv")
  end
end
