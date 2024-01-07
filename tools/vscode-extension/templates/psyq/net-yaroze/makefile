TARGET = {{projectName}}
TYPE = ps-exe

SRCS = \
third_party/nugget/common/crt0/crt0.s \
main.c
#-fpermissive

CPPFLAGS += -Wfatal-errors -Werror -msoft-float -Ithird_party/psyq-iwyu/include -Ithird_party/net-yaroze/include
LDFLAGS=-Xlinker --defsym=TLOAD_ADDR=0x80090000 
LDFLAGS += -Lthird_party/psyq/lib
LDFLAGS += -Wl,--start-group
LDFLAGS += -lc
LDFLAGS += -lc2
LDFLAGS += -lapi
LDFLAGS += -lcard
LDFLAGS += -lcd
LDFLAGS += -lcomb
LDFLAGS += -lds
LDFLAGS += -letc
LDFLAGS += -lgpu
LDFLAGS += -lgs
LDFLAGS += -lgte
LDFLAGS += -lgun
LDFLAGS += -lhmd
LDFLAGS += -lmath
LDFLAGS += -lmcrd
LDFLAGS += -lmcx
LDFLAGS += -lpad
LDFLAGS += -lpress
LDFLAGS += -lsio
LDFLAGS += -lsnd
LDFLAGS += -lspu
LDFLAGS += -ltap
LDFLAGS += -Wl,--end-group

include third_party/nugget/common.mk