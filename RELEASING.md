# Releasing

apparitor publishes to PyPI from a tagged commit via GitHub Actions
([`.github/workflows/release.yml`](.github/workflows/release.yml)). Releases use PyPI
Trusted Publishing (OIDC); there is no API token to manage.

## Versioning

The published version is single-sourced from `__version__` in
[`src/apparitor/__init__.py`](src/apparitor/__init__.py) — hatch reads it as the package's
dynamic version. The git tag only *triggers* the release; it does not set the version. The
two must agree, and CI fails a tagged build when `vX.Y.Z` does not match `__version__`.

The project follows [Semantic Versioning](https://semver.org/) and stays on the `0.x` line
while the public API may still change. A `1.0.0` is a commitment that the API is stable (no
breaking changes before `2.0`), and a release on PyPI is permanent — don't reach for `1.0`
until that promise holds.

## Cut a release

1. On a branch, bump `__version__` in `src/apparitor/__init__.py` and add the matching
   section to [`CHANGELOG.md`](CHANGELOG.md). Open a PR and merge it to `main`.
2. From the merged commit on `main`, push a **bare tag** — do not pre-create the GitHub
   release in the UI (see [SBOM and immutable releases](#sbom-and-immutable-releases)):

   ```bash
   git checkout main && git pull
   git tag vX.Y.Z            # must equal __version__
   git push origin vX.Y.Z
   ```

3. The workflow runs the full gate (ruff, mypy, pytest on 3.10 / 3.12), builds the sdist +
   wheel, publishes to PyPI, and creates the GitHub release with a CycloneDX SBOM attached.
   Watch it under the repository's Actions tab.

A `workflow_dispatch` run is available for re-runs; dispatch it **from the tag**, not from
`main` — the `pypi` environment is restricted to tags, and you want the tagged commit.

## One-time setup (maintainer)

Trusted Publishing needs two things configured once, outside the repository:

- **PyPI** — add a publisher at <https://pypi.org/manage/account/publishing/> (a *pending*
  publisher if the project does not exist on PyPI yet). Project `apparitor`, owner
  `counterbranch`, repository `apparitor`, workflow `release.yml`, environment `pypi`. These
  fields must match the workflow exactly, or the `publish` job fails the OIDC exchange.
- **GitHub** — a `pypi` environment (Settings → Environments), ideally restricted to `v*`
  tags so only tagged runs can publish.

After transferring the repository, verify the PyPI publisher owner is `counterbranch`
and the GitHub `pypi` environment still has the intended tag restriction before
a release. Repository redirects do not update PyPI publisher identities.

## SBOM and immutable releases

The release attaches a CycloneDX SBOM to the GitHub release. If the repository has
**immutable releases** enabled, assets can only be added at creation time, so let the
workflow create the release (push a bare tag). If you pre-create the release in the UI it
locks on publish and the SBOM cannot be attached afterward (`HTTP 422`); the workflow
downgrades that to a warning and the SBOM remains downloadable as the run's `sbom`
artifact.
