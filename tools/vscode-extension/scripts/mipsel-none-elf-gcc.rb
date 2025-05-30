class MipselNoneElfGcc < Formula
  desc "The GNU compiler collection for mipsel"
  homepage "https://gcc.gnu.org"
  url "https://ftpmirror.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz"
  mirror "https://mirrors.kernel.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz"
  sha256 "a7b39bc69cbf9e25826c5a60ab26477001f7c08d85cec04bc0e29cabed6f3cc9"

  depends_on "gmp"
  depends_on "mipsel-none-elf-binutils"
  depends_on "libmpc"
  depends_on "mpfr"
  depends_on "gnu-sed"

  def install
    ENV.prepend_path "PATH", Formula["gnu-sed"].opt_libexec/"gnubin"
    mkdir "mipsel-none-elf-gcc-build" do
      system "../configure", "--target=mipsel-none-elf",
                             "--prefix=#{prefix}",
                             "--without-isl",
                             "--disable-nls",
                             "--disable-threads",
                             "--disable-shared",
                             "--disable-libssp",
                             "--disable-libstdcxx-pch",
                             "--disable-libgomp",
                             "--disable-werror",
                             "--without-headers",
                             "--disable-hosted-libstdcxx",
                             "--with-as=#{Formula["mipsel-none-elf-binutils"].bin}/mipsel-none-elf-as",
                             "--with-ld=#{Formula["mipsel-none-elf-binutils"].bin}/mipsel-none-elf-ld",
                             "--enable-languages=c,c++"
      system "make", "all-gcc"
      system "make", "install-strip-gcc"
      system "make", "all-target-libgcc"
      system "make", "install-strip-target-libgcc"
      system "make", "all-target-libstdc++-v3"
      system "make", "install-strip-target-libstdc++-v3"
    end
  end

  test do
    (testpath/"test-c.c").write <<~EOS
      int main(void)
      {
        int i=0;
        while(i<10) i++;
        return i;
      }
    EOS
    system "#{bin}/mipsel-none-elf-gcc", "-c", "-o", "test-c.o", "test-c.c"
  end
end
