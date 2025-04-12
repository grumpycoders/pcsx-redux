ifndef PSYQOPATHSDIR
PSYQOPATHSDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

LIBRARIES += $(PSYQOPATHSDIR)libpsyqo-paths.a

include $(PSYQOPATHSDIR)../psyqo/psyqo.mk

$(PSYQOPATHSDIR)libpsyqo-paths.a:
	$(MAKE) -C $(PSYQOPATHSDIR) BUILD=$(BUILD)

clean::
	$(MAKE) -C $(PSYQOPATHSDIR) clean

.PHONY: clean-psyqo-paths $(PSYQOPATHSDIR)libpsyqo-paths.a
endif
