#!/bin/bash
set -e
pkg=$1
set -x
(
    cd ${pkg}
    rm -rf MANIFEST
    set +e
    mkdir dist
    set -e
    git tag -f v99.9.9.a0 HEAD
    ( cd dist && git init && git rm --quiet -rf --ignore-unmatch -- * )
    if [ ${pkg} == "master" ] || [ ${pkg} == "worker" ] || [ ${pkg} == "pkg" ]; then
        python -m build --no-isolation --sdist --outdir dist/with-deps
        (cd dist/with-deps && tar -xzf *.tar.gz && rm *.tar.gz)
        NO_INSTALL_REQS=1 python -m build --no-isolation --sdist --outdir dist/no-deps
        (cd dist/no-deps && tar -xzf *.tar.gz && rm *.tar.gz)
        # wheels must be build separately in order to properly omit tests
        python -m build --no-isolation --wheel --outdir dist/with-deps
        (cd dist/with-deps && python -m wheel unpack --dest wheel-out *.whl && rm *.whl)
        NO_INSTALL_REQS=1 python -m build --no-isolation --wheel --outdir dist/no-deps
        (cd dist/no-deps && python -m wheel unpack --dest wheel-out *.whl && rm *.whl)
    else
        # retry once to workaround instabilities
        python -m build --no-isolation || (git clean -xdf; python -m build --no-isolation)
    fi
    git_msg=`git log -1 --oneline --no-decorate`
    ( cd dist && git add --no-verbose -f -- * && git commit --allow-empty -m "${git_msg}")
)
# cp ${pkg}/dist/* dist/
