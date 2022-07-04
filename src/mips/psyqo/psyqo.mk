PSYQODIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

LIBRARIES += $(PSYQODIR)libpsyqo.a
CPPFLAGS += -I../../../../../third_party/EASTL/include -I../../../../../third_party/EABase/include/Common

EXTRA_CLEAN += clean-psyqo

include $(PSYQODIR)../common.mk

$(PSYQODIR)libpsyqo.a:
	$(MAKE) -C $(PSYQODIR)

clean-psyqo:
	$(MAKE) -C $(PSYQODIR) clean

.PHONY: clean-psyqo $(PSYQODIR)libpsyqo.a
