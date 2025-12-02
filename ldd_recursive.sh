#!/bin/bash
# Use: ./ldd_recursive.sh /route/to/binary

lib_count=0

if [[ $# -ne 3 ]]; then
    echo "Uso: $0 /ruta/a/ejecutable <elf_name> /directorio/output"
    exit 1
fi

LOGFILE="$3/ldd_logfile_$2.log"
: > "$LOGFILE"
RESULTFILE="$3/ldd_resultfile_$2.xml"
: > "$RESULTFILE"

extract_name_and_version() {
    local f="$1"
    f="${f%.so}"  # quita la extensión .so si la hay

    local name version

    # Caso típico: algo.so.X o algo.so.X.Y.Z
    if [[ "$f" == *.so.* ]]; then
        name="${f%%.so.*}"
        version="${f#*.so.}"
    else
        # Caso con guiones: foo-1.2.3.so, ld-linux-x86-64.so.2
        name="${f%%[-0-9.]*}"
        version="${f#$name}"
        version="${version#[-.]}"
    fi

    [[ -z "$version" ]] && version="unknown"

    echo "$name $version"
}

function analyse() {

	local bin_dir="$1"
	local bin_name="$2"
	local bin_type="$3"
	local bin_linkname="$4"
	local bin_linkdir="$5"
    local nivel="$6"

	local indent
	
	lib_count=$((lib_count + 1))

	indent=$(printf "%*s" $((nivel * 2)) "")
	child_indent=$(printf "%*s" $(((nivel + 1) * 2)) "")
	gc_indent=$(printf "%*s" $(((nivel + 2) * 2)) "")
	ggc_indent=$(printf "%*s" $(((nivel + 3) * 2)) "")

    if [ $bin_linkname ]; then
		read lib_name lib_vers <<< "$(extract_name_and_version "$bin_linkname")"
	else
		read lib_name lib_vers <<< "$(extract_name_and_version "$bin_name")"
	fi

    # Open XML object
	printf '%s<component type=\"%s\">\n' "$indent" "$bin_type" >> $RESULTFILE
	printf '%s<filename>%s</filename>\n' "$child_indent" "$bin_linkname" >> $RESULTFILE
	printf '%s<name>%s</name>\n' "$child_indent" "$lib_name" >> $RESULTFILE
	printf '%s<version>%s</version>\n' "$child_indent" "$lib_vers" >> $RESULTFILE
	printf '%s<path>%s</path>\n' "$child_indent" "$bin_linkdir" >> $RESULTFILE
	printf '%s<hashes>\n' "$child_indent" >> $RESULTFILE
	printf '%s<hash alg=\"MD5\">%s</hash>\n' "$gc_indent" "$(md5sum "$bin_dir" | awk '{print $1}')" >> $RESULTFILE
	# printf '%s<hash alg=\"SHA256\">%s</hash>\n' "$gc_indent" "$(sha256sum "$bin_dir" | awk '{print $1}')" >> $RESULTFILE
	printf '%s</hashes>\n' "$child_indent" >> $RESULTFILE
	
	if [ $bin_linkname ]; then
		
		printf '%s<externalReferences>\n' "$child_indent" >> $RESULTFILE
		printf '%s<reference>\n' "$gc_indent" >> $RESULTFILE
		printf '%s<filename>%s</filename>\n' "$ggc_indent" "$bin_name" >> $RESULTFILE
		printf '%s<url>%s</url>\n' "$ggc_indent" "$bin_dir" >> $RESULTFILE
		printf '%s<comment>Symbolic Link</comment>\n' "$ggc_indent" >> $RESULTFILE
		printf '%s</reference>\n' "$gc_indent" >> $RESULTFILE
		printf '%s</externalReferences>\n' "$child_indent" >> $RESULTFILE
		
	fi

	printf '%s<dependencies>\n' "$child_indent" >> $RESULTFILE

	
	while read -r name dir; do
	#ldd "$1" 2>/dev/null | awk '{print $1, $3}' | while read -r name dir; do
		
		# Check if the name is a directory
		if [[ "$name" == /* ]]; then
			dir="$name"
			name=$(basename "$dir")
		fi
		
		# Check if name is really a .so (library)
		if [[ ! "$name" == *.so* ]]; then
			continue
		fi
		
		lib="$name"
		link_dir="$dir"
		
		# In case the library can not be found in the system
		if [[ ! "$dir" == /* ]]; then
			dir=""
		fi
		
		if [[ "$nivel" -eq 0 ]]; then
			printf "\n==================== %s ====================\n\n" "$name" >> $LOGFILE # | tee -a $LOGFILE
		fi
		
		printf "%*s[+] %s\n" $((nivel * 3)) "" "Name: $name" >> $LOGFILE # | tee -a $LOGFILE
		printf "%*s[-] %s\n" $((nivel * 3)) "" "Dir: $dir" >> $LOGFILE # | tee -a $LOGFILE
		
		# Look if any symbolical link exists on the .so dir
		if [[ -L "$dir" ]]; then
			link_dir=$(readlink "$dir")
			
			if [[ "$link_dir" == /* ]]; then
				lib=$(basename "$link_dir")
			else
				lib="$link_dir"
				link_dir="${dir%/*}/$lib"
			fi
			
			printf "%*s[-] Link: %s -> %s\n" $((nivel * 3)) "" "$dir ($name)" "$link_dir ($lib)" >> $LOGFILE # | tee -a $LOGFILE
		fi
		
		# If string is empty do not print directory
		if [[ -z "$dir" || "$dir" == "$bin_dir" ]]; then
			continue
		fi
		
		echo -ne "\r[i] Lib Count: $lib_count"
		
		# Original dir, Original Name, Type, SymbLink Name, SimbLink Dir, Level
		analyse "$dir" "$name" "library" "$lib" "$link_dir" $((nivel + 2))
		
	done < <(ldd "$1" 2>/dev/null | grep -vE 'linux-vdso\.so\.1|ld-linux.*\.so\.[0-9]+' | awk '{print $1, $3}')	
	#done

	printf '%s  </dependencies>\n' "$child_indent" >> $RESULTFILE
	printf '%s</component>\n' "$indent" >> $RESULTFILE

	# # Close json object
	# printf "\n%s  ]\n" "$indent" >> $RESULTFILE
	# printf "%s},\n" "$indent" >> $RESULTFILE

}

analyse "$1" "$2" "application" "" "" 0 

printf "\n"