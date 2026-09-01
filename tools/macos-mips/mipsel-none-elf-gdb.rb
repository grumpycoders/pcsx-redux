class MipselNoneElfGdb < Formula
  desc "GDB: The GNU Project Debugger compiled for Mips"
  homepage "https://sourceware.org/gdb/"
  url "https://ftpmirror.gnu.org/gnu/gdb/gdb-16.3.tar.xz"
  mirror "https://mirrors.kernel.org/gnu/gdb/gdb-16.3.tar.xz"
  sha256 "bcfcd095528a987917acf9fff3f1672181694926cc18d609c99d0042c00224c5"

  # inspired by https://github.com/orgs/Homebrew/discussions/1114#discussioncomment-8863715

  depends_on "texinfo" => :build
  depends_on "gmp"
  depends_on "mpfr"
  depends_on "python@3.10"

  def install
    mkdir "mipsel-none-elf-gdb-build" do
      system "../configure", "--target=mipsel-none-elf",
                             "--prefix=#{prefix}",
                             "--enable-tui=yes",
                             "--without-isl",
                             "--disable-werror"
      system "make"
      system "make", "install"
    end
  end

  # not sure what to test...
  # test do
  #   assert_match "f()", shell_output("#{bin}/mipsel-none-elf-c++filt _Z1fv")
  # end

end
