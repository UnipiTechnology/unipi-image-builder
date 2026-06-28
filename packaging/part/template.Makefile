
PREREQ_FILES := {{build_dir}}/.format.yaml {{build_dir}}/.Makefile.part

include {{build_dir}}/.Makefile.volumes

{{image}}: $(VOLUME_FILES) $(PREREQ_FILES)
	for V in $(RAW_FILES); do\
	     cp "$$(echo $$V | cut -d: -f2)" {{image}}.part$$(echo $$V | cut -d: -f1);\
	done
	touch "$@"