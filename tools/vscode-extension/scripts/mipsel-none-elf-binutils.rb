class MipselNoneElfBinutils < Formula
  desc "FSF Binutils for mipsel cross development"
  homepage "https://www.gnu.org/software/binutils/"
  url "https://ftpmirror.gnu.org/gnu/binutils/binutils-2.46.1.tar.gz"
  mirror "https://mirrors.kernel.org/gnu/binutils/binutils-2.46.1.tar.gz"
  sha256 "364c8faa19ea46c44089c2d59c1fee6eda9a273787d0fe8ab9dfb249069c6aee"

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
