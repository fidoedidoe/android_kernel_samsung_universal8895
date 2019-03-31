NAME ?= RZ_kernel

DATE := $(shell date +'%Y%m%d-%H%M')

ZIP := $(NAME)-$(DEVICE)-$(DATE).zip

EXCLUDE := \
	Makefile README.md *.git* "$(NAME)-"*.zip* \
	rz_system/vendor/firmware_**\* \

all: $(ZIP)

$(ZIP):
	@echo "Creating ZIP: $(ZIP)"
	@zip -r9 "$@" . -x $(EXCLUDE)
	@echo "Generating SHA1..."
	@sha1sum "$@" > "$@.sha1"
	@cat "$@.sha1"
	@echo "Done."

clean:
	@rm -vf "$(NAME)-"*.zip*
	@rm -rf rz_system/vendor/firmware
	@echo "Done."
