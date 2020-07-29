#!/bin/bash

function check_libs {
    local elf_path=$1

    for elf in $(find $elf_path -maxdepth 1 -exec file {} \; | grep 'ELF ' | cut -d':' -f1); do
        echo "$elf"
        ldd "$elf"
    done
    return
}

function prepare {
    CURDIR=$(pwd)
    TMP_DIR="$CURDIR/temp"

    mkdir -p "$CURDIR"/temp
    mkdir -p "$TMP_DIR"/db "$TMP_DIR"/tests

    TARBALL=$(basename $(find . -name "*.tar.gz" | sort))
    DIRLIST="bin lib/private"
}

function install_deps {
    if [ -f /etc/redhat-release ]; then
        yum install -y epel-release
        yum install -y wget perl-Time-HiRes perl numactl numactl-libs libaio libidn || true
    else
        apt install -y wget perl numactl libaio-dev libidn11 || true
    fi
}

main () {
    prepare
    echo "Unpacking tarball"
    cd "$TMP_DIR"
    tar xf "$CURDIR/$TARBALL"
    cd "${TARBALL%.tar.gz}"

    echo "Building ELFs ldd output list"
    for DIR in $DIRLIST; do
        if ! check_libs "$DIR" >> "$TMP_DIR"/libs_err.log; then
            echo "There is an error with libs linkage"
            echo "Displaying log: "
            cat "$TMP_DIR"/libs_err.log
            exit 1
        fi
    done

    echo "Checking for missing libraries"
    if [[ ! -z $(grep "not found" $TMP_DIR/libs_err.log) ]]; then
        echo "ERROR: There are missing libraries: "
        grep "not found" "$TMP_DIR"/libs_err.log
        echo "Log: "
        cat "$TMP_DIR"/libs_err.log
        exit 1
    fi

    wget -O "$TMP_DIR"/mgodatagen.tar.gz https://github.com/feliixx/mgodatagen/releases/download/v0.8.2/mgodatagen_linux_x86_64.tar.gz
    wget -O "$TMP_DIR"/tests/big.json https://raw.githubusercontent.com/feliixx/mgodatagen/master/datagen/testdata/big.json
    tar -xvf "$TMP_DIR"/mgodatagen.tar.gz

    ./bin/mongod --dbpath $TMP_DIR/db 2>&1 > status.log &
    MONGOPID="$(echo $!)"
    ./mgodatagen -f "$TMP_DIR"/tests/big.json
    if [[ "$?" -eq 0 ]]; then
        echo "Tests succeeded"
        kill -2 "$MONGOPID"
        echo "== PSMDB Log =="
        cat status.log
    else
        echo "Tests failed"
        exit 1
    fi
}

case "$1" in
    --install_deps) install_deps ;;
    --test) main ;;
    --help|*)
    cat <<EOF
Usage: $0 [OPTIONS]
    The following options may be given :
        --install_deps
        --test
        --help) usage ;;
Example $0 --install_deps 
EOF
    ;;
esac
