#!/bin/bash

if test $(git rev-parse --abbrev-ref HEAD) = "master"; then
    if test -z "$(git status --untracked-files=no --porcelain)"; then
        MSG="$(git log -1 --pretty=%B)"
        echo "$MSG" | grep "Bump version"
        if test $? -eq 0; then
            VERSION=$(echo "$MSG" | awk -F→ '{print $2}')
            echo "---------------------------------------------------"
            echo "Releasing version ${VERSION} ..."
            echo "---------------------------------------------------"
            echo
            echo
            git checkout build
            git merge master
            echo "Pushing build to origin ..."
            git push --tags origin build
            git checkout master
            # We do this sleep here so our codepipeline can be triggered on the build push
            # If you push master and build simultaneously, the pipeline gets confused and
            # won't trigger.  Possibly master triggers the pipeline first and then the build
            # push notification gets lost in a race condition.
            echo "Sleeping 3 seconds to allow the build push to trigger the CodePipeline ..."
            sleep 3
            echo "Pushing master to origin ..."
            git push origin master
        else
            echo "Last commit was not a bumpversion; aborting."
            echo "Last commit message: ${MSG}"
        fi
    else
        git status
        echo
        echo
        echo "------------------------------------------------------"
        echo "You have uncommitted changes; aborting."
        echo "------------------------------------------------------"
    fi
else
    echo "You're not on master; aborting."
fi
