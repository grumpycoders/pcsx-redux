ifndef SNITCHDIR
SNITCHDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))snitch/

LIBRARIES += $(SNITCHDIR)libsnitch.a
CPPFLAGS += -I$(SNITCHDIR)../../../../third_party/snitch

include $(SNITCHDIR)../../psyqo/psyqo.mk

$(SNITCHDIR)libsnitch.a:
	$(MAKE) -C $(SNITCHDIR) BUILD=$(BUILD)

clean::
	$(MAKE) -C $(SNITCHDIR) clean

.PHONY: clean $(SNITCHDIR)libsnitch.a
endif
