class MipselNoneElfGcc < Formula
  desc "The GNU compiler collection for mipsel"
  homepage "https://gcc.gnu.org"
  url "https://ftpmirror.gnu.org/gnu/gcc/gcc-15.2.0/gcc-15.2.0.tar.xz"
  mirror "https://mirrors.kernel.org/gnu/gcc/gcc-15.2.0/gcc-15.2.0.tar.xz"
  sha256 "438fd996826b0c82485a29da03a72d71d6e3541a83ec702df4271f6fe025d24e"

  depends_on "gmp"
  depends_on "mipsel-none-elf-binutils"
  depends_on "libmpc"
  depends_on "mpfr"
  depends_on "gnu-sed"

  patch :DATA

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

__END__
diff --git a/zlib/zutil.h b/zlib/zutil.h
index 0bd2dbcba..bb513cb4b 100644
--- a/zlib/zutil.h
+++ b/zlib/zutil.h
@@ -130,17 +130,8 @@
 #  endif
 #endif

-#if defined(MACOS) || defined(TARGET_OS_MAC)
+#if defined(MACOS)
 #  define OS_CODE  7
-#  ifndef Z_SOLO
-#    if defined(__MWERKS__) && __dest_os != __be_os && __dest_os != __win32_os
-#      include <unix.h> /* for fdopen */
-#    else
-#      ifndef fdopen
-#        define fdopen(fd,mode) NULL /* No fdopen() */
-#      endif
-#    endif
-#  endif
 #endif

 #ifdef __acorn
@@ -163,19 +154,12 @@
 #  define OS_CODE 19
 #endif

-#if defined(_BEOS_) || defined(RISCOS)
-#  define fdopen(fd,mode) NULL /* No fdopen() */
-#endif
-
 #if (defined(_MSC_VER) && (_MSC_VER > 600)) && !defined __INTERIX
 #  if defined(_WIN32_WCE)
-#    define fdopen(fd,mode) NULL /* No fdopen() */
 #    ifndef _PTRDIFF_T_DEFINED
        typedef int ptrdiff_t;
 #      define _PTRDIFF_T_DEFINED
 #    endif
-#  else
-#    define fdopen(fd,type)  _fdopen(fd,type)
 #  endif
 #endif
