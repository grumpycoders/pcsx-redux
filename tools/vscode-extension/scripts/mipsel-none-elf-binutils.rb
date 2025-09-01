class MipselNoneElfBinutils < Formula
  desc "FSF Binutils for mipsel cross development"
  homepage "https://www.gnu.org/software/binutils/"
  url "https://ftpmirror.gnu.org/gnu/binutils/binutils-2.45.tar.gz"
  mirror "https://mirrors.kernel.org/gnu/binutils/binutils-2.45.tar.gz"
  sha256 "8a3eb4b10e7053312790f21ee1a38f7e2bbd6f4096abb590d3429e5119592d96"

  depends_on "texinfo" => :build

  patch :DATA

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

__END__
diff --git a/zlib/zutil.h b/zlib/zutil.h
index 0bd2dbcba..bb513cb4b 100644
--- a/zlib/zutil.h
+++ b/zlib/zutil.h
@@ -137,17 +137,8 @@ extern z_const char * const z_errmsg[10]; /* indexed by 2-zlib_error */
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
@@ -170,18 +161,6 @@ extern z_const char * const z_errmsg[10]; /* indexed by 2-zlib_error */
 #  define OS_CODE 19
 #endif

-#if defined(_BEOS_) || defined(RISCOS)
-#  define fdopen(fd,mode) NULL /* No fdopen() */
-#endif
-
-#if (defined(_MSC_VER) && (_MSC_VER > 600)) && !defined __INTERIX
-#  if defined(_WIN32_WCE)
-#    define fdopen(fd,mode) NULL /* No fdopen() */
-#  else
-#    define fdopen(fd,type)  _fdopen(fd,type)
-#  endif
-#endif
-
 #if defined(__BORLANDC__) && !defined(MSDOS)
   #pragma warn -8004
   #pragma warn -8008
