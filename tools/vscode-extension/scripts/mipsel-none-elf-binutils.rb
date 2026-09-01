class MipselNoneElfBinutils < Formula
  desc "FSF Binutils for mipsel cross development"
  homepage "https://www.gnu.org/software/binutils/"
  url "https://ftpmirror.gnu.org/gnu/binutils/binutils-2.47.tar.gz"
  mirror "https://mirrors.kernel.org/gnu/binutils/binutils-2.47.tar.gz"
  sha256 "15f5abd0db9cf8ea116f516a9ce12bc1cefef491ef9e50942868093d8f92a6f3"

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
