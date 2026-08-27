# Release

`github.com/Agent-Card/ai-catalog-go` is a single Go module. A release is cut by pushing a semver tag — there is no version string to bump in the source tree, and consumers fetch the module through the Go module proxy rather than downloading artifacts.

Examples below use `v1.0.0`; substitute the version being released.

## 1. Verify main

Check out the commit to be released and confirm it is green.

```sh
git checkout main
git pull origin main
task test
task lint
task license
```

## 2. Create and push the tag

```sh
git tag -a v1.0.0 -m "v1.0.0"
git push origin v1.0.0
```

Pushing a `v*.*.*` tag triggers the [release workflow](.github/workflows/release.yaml), which creates a GitHub Release with generated notes.

> [!IMPORTANT]
> Published versions cannot be retracted. The Go module proxy caches a version permanently the first time it is fetched, so deleting or moving a tag does not unpublish it. If a release is broken, tag a new patch version.

## 3. Verify the release

* Confirm the release workflow completed successfully.
* Check the [Releases page](https://github.com/Agent-Card/ai-catalog-go/releases) for the new entry and its generated notes. The release carries no build assets.
* Confirm the version resolves through the proxy:

```sh
GOPROXY=proxy.golang.org go list -m github.com/Agent-Card/ai-catalog-go@v1.0.0
```

Documentation for the new version appears on [pkg.go.dev](https://pkg.go.dev/github.com/Agent-Card/ai-catalog-go) shortly after the first fetch.
