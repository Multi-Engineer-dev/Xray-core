# Working on this fork

This repository is our fork of [XTLS/Xray-core](https://github.com/XTLS/Xray-core). We run it as our own Xray and inside our build of [PasarGuard node](https://github.com/PasarGuard/node), and we merge upstream into it often. Every change has to keep two things true: the next upstream merge stays easy, and official Xray clients keep working against our servers.

## Branches

- `main` mirrors `XTLS/Xray-core` `main`. Never commit to it; it is only fast-forwarded with `gh repo sync <owner>/Xray-core --branch main`.
- `dev` is the default branch: `main` plus our changes. PRs target `dev`.
- Upstream reaches `dev` through a merge of `upstream/main` in its own PR. Merge that PR with "Create a merge commit". A squash or rebase leaves upstream's commits out of `dev`, and the next sync conflicts again.
- A change meant for upstream starts from `main`, so the same branch can also be opened against XTLS/Xray-core.

## Keep the diff against upstream small

`git diff upstream/main...dev` is what every future merge has to carry, so keep each change to it as small as possible:

- Put new code and new tests in new files instead of growing upstream files.
- When an upstream function has to change, change only the lines that need it. Don't rename, move, reorder, reformat, extract helpers from, or reword upstream code or comments.
- Leave files that upstream owns alone unless the change needs them: `README.md`, `go.mod`/`go.sum`, `core/core.go`, and upstream's workflows. Our CI goes in its own workflow files (`build.yml`, `upstream.yml`, `interop.yml`, `node.yml`).
- Don't change `.proto` files, generated `*.pb.go` files, or config parsing in `infra/conf`. They define what panels and official clients send us, and upstream regenerates them all the time. If a change really needs them, ask first.
- Write notes about fork behavior as code comments next to the code, or in the PR description, not in `README.md`.

Two examples from this repo:

- Bad: appending a benchmark to upstream's `proxy/tun/udp_fullcone_test.go`, so that every upstream edit to that file conflicts with ours. Good: putting it in `proxy/tun/udp_bench_test.go`, a file only we have (#7).
- Bad: moving the listener closure in upstream's `NewClient` into a new function, just to add to it. Good: adding the few lines we need inside the closure, and leaving the rest as it is (#8).

## When upstream has the same change

If upstream lands its own version of something we carry, take upstream's version and drop ours, even if ours differs in detail. For example, upstream's #7151 replaced our WireGuard setup fix in #8. Keep only one implementation of anything.

## Compatibility with official clients

An official Xray client of the latest stable release, and of the newest pre-release, must connect to our server over every protocol. `TestUpstreamClient` in `testing/scenarios/interop_test.go` checks this against a downloaded official binary, and the `Upstream clients` workflow runs it in CI. To run it locally:

```sh
XRAY_UPSTREAM=/path/to/official/xray go test -run TestUpstreamClient ./testing/scenarios
```

If a case fails, run it again with `XRAY_SERVER` set to the official release our `dev` is based on, to tell our failures from upstream's. When you add a protocol or transport to our servers, add a case for it.

## Before opening a PR

- Base the branch on the current `dev`, and keep one logical change per commit. Write subjects the way upstream does, e.g. `SS2022 inbound: End a UDP session with the connection that carries its replies`.
- Run `go run ./infra/vformat/main.go -mode check -pwd ./`, `go build ./...`, and `go test` for the packages you touched. Add `-race` for concurrent code.
- Check that upstream still merges into your branch: `git fetch https://github.com/XTLS/Xray-core.git main && git merge --no-commit --no-ff FETCH_HEAD`, then `git merge --abort`.

## Resolving an upstream merge

- For each conflicted file, start from upstream's version, then port our change onto it with the smallest diff that works.
- Afterwards, check that `git diff upstream/main...HEAD` changed only where you meant it to; every other hunk should add and remove the same lines as before.
- Run the full test suite and `TestUpstreamClient` before opening the PR.
