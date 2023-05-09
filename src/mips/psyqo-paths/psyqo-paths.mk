PSYQOPATHSDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

LIBRARIES += $(PSYQOPATHSDIR)libpsyqo-paths.a

EXTRA_CLEAN += clean-psyqo-paths

include $(PSYQOPATHSDIR)../psyqo/psyqo.mk

$(PSYQOPATHSDIR)libpsyqo-paths.a:
	$(MAKE) -C $(PSYQOPATHSDIR) BUILD=$(BUILD)

clean-psyqo-paths:
	$(MAKE) -C $(PSYQOPATHSDIR) clean

.PHONY: clean-psyqo-paths $(PSYQOPATHSDIR)libpsyqo-paths.a
