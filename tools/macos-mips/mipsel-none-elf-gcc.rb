class MipselNoneElfGcc < Formula
  desc "The GNU compiler collection for mipsel"
  homepage "https://gcc.gnu.org"
  url "https://ftpmirror.gnu.org/gnu/gcc/gcc-16.2.0/gcc-16.2.0.tar.xz"
  mirror "https://mirrors.kernel.org/gnu/gcc/gcc-16.2.0/gcc-16.2.0.tar.xz"
  sha256 "e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e"

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
