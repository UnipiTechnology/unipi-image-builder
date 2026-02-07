
PREQ_FILES := {{build_dir}}/.format.yaml {{build_dir}}/.Makefile.volumes {{build_dir}}/.mountpoints
ETC_FILES += {{build_dir}}/archive/etc/fstab {{build_dir}}/archive/etc/default/switchboot

{##### Create list of volume files #####}
{% for volume in images -%}
VOLUME_FILES += {{build_dir}}/archive/{{volume.partition.name}}.{{volume.fs_type}}
{% endfor -%}
{% for volume in cpios -%}
VOLUME_FILES += {{build_dir}}/archive/{{volume.subvol | default(volume.partition.name)}}.cpio
{% endfor %}
{% for volume in images | sort(attribute="partition.part_num") -%}
RAW_FILES += {{volume.partition.part_num}}:{{build_dir}}/archive/{{volume.partition.name}}.{{volume.fs_type}}
{% endfor %}

{% for volume in images+cpios if volume.mount_point != '/' -%}
MOUNT_POINTS += {{volume.mount_point}}
{% endfor %}

{{build_dir}}/.mountpoints: {{tar}} {{build_dir}}/.format.yaml {{build_dir}}/.Makefile.volumes
	@if [ -n "$(MOUNT_POINTS)" ]; then \
	    mkdir -p $(patsubst %,{{build_dir}}/archive%, $(MOUNT_POINTS)); \
	    tar uf {{tar}} -C {{build_dir}}/archive $(patsubst %,.%, $(MOUNT_POINTS)); \
	fi
	@touch $@

volumes: $(VOLUME_FILES)

{##### Create rules for volume files #####}
{% for img in images -%}
{% with volume=img %}{% include "volumes/_volumes/template.mkimage" %}{% endwith %}
{% endfor %}

{% for cpio in cpios -%}
{% with volume=cpio %}{% include "volumes/_volumes/template.mkcpio" %}{% endwith %}
{% endfor -%}
