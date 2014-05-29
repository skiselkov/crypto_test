UTSBASE	= /code/illumos-gate/usr/src/uts

MODULE		= crypto_test
OBJECTS		= crypto_test.o
LINTS		= $(OBJECTS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_CRYPTO_DIR)/$(MODULE)
ROOTLINK	= $(ROOT_MISC_DIR)/$(MODULE)

include $(UTSBASE)/intel/Makefile.intel

ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK)

LDFLAGS += -dy
# -Ncrypto/cmac

.KEEP_STATE:

def:		$(DEF_DEPS)
all:		$(ALL_DEPS)
clean:		$(CLEAN_DEPS)
clobber:	$(CLOBBER_DEPS)
lint:		$(LINT_DEPS)
modlintlib:	$(MODLINTLIB_DEPS)
clean.lint:	$(CLEAN_LINT_DEPS)
install:	$(INSTALL_DEPS)

$(ROOTLINK):	$(ROOT_MISC_DIR) $(ROOTMODULE)
	-$(RM) $@; ln $(ROOTMODULE) $@

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

CTFMERGE	= true
