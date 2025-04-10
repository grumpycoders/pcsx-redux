ifndef PSYQOLUADIR
PSYQOLUADIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

LIBRARIES += $(PSYQOLUADIR)libpsyqo-lua.a $(PSYQOLUADIR)../../../third_party/psxlua/src/liblua.a

CPPFLAGS += -I$(PSYQOLUADIR)../../../third_party/psxlua/src

LDFLAGS += \
-Wl,--defsym,luaI_sprintf=sprintf_for_Lua \
-Wl,--defsym,luaI_realloc=psyqo_realloc \
-Wl,--defsym,luaI_free=psyqo_free \

EXTRA_CLEAN += clean-psyqo-lua

include $(PSYQOLUADIR)../psyqo/psyqo.mk

$(PSYQOLUADIR)libpsyqo-lua.a:
	$(MAKE) -C $(PSYQOLUADIR) BUILD=$(BUILD)

$(PSYQOLUADIR)../../../third_party/psxlua/src/liblua.a:
	$(MAKE) -C $(PSYQOLUADIR)../../../third_party/psxlua psx

clean-psyqo-lua:
	$(MAKE) -C $(PSYQOLUADIR) clean
	$(MAKE) -C $(PSYQOLUADIR)../../../third_party/psxlua clean

.PHONY: clean-psyqo-lua $(PSYQOLUADIR)libpsyqo-lua.a $(PSYQOLUADIR)../../../third_party/psxlua/src/liblua.a
endif
