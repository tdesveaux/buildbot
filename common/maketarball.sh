#!/bin/bash
set -e
pkg=$1
(
    cd ${pkg}
    rm -rf MANIFEST dist
    if [ ${pkg} == "master" ] || [ ${pkg} == "worker" ] || [ ${pkg} == "pkg" ]; then
        python -m build --sdist
        # wheels must be build separately in order to properly omit tests
        python -m build --wheel
    else
        # retry once to workaround instabilities
        python -m build --no-isolation || (git clean -xdf; python -m build --no-isolation)
    fi
)
cp ${pkg}/dist/* dist/
