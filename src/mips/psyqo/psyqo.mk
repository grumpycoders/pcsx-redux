ifndef PSYQODIR
PSYQODIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

LIBRARIES += $(PSYQODIR)libpsyqo.a
CPPFLAGS += -I$(PSYQODIR)../../../third_party/EASTL/include -I$(PSYQODIR)../../../third_party/EABase/include/Common
CXXFLAGS += -std=c++20

include $(PSYQODIR)../common.mk

$(PSYQODIR)libpsyqo.a:
	$(MAKE) -C $(PSYQODIR) BUILD=$(BUILD) CPPFLAGS_$(BUILD)="$(CPPFLAGS_$(BUILD))" LDFLAGS_$(BUILD)="$(LDFLAGS_$(BUILD))"

clean::
	$(MAKE) -C $(PSYQODIR) clean

.PHONY: clean $(PSYQODIR)libpsyqo.a
endif
