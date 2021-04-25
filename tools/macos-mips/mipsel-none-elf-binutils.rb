class MipselNoneElfBinutils < Formula
  desc "FSF Binutils for mipsel cross development"
  homepage "https://www.gnu.org/software/binutils/"
  url "https://ftp.gnu.org/gnu/binutils/binutils-2.36.1.tar.gz"
  sha256 "e68edeaaeb6ca9687b6dcbaedd1b376506baad2d48de26a885fc5ab6acb839da"

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
