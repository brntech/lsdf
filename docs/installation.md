# Installation

Use Docker Desktop with Linux containers on Windows/macOS, or Docker Engine with the Compose plugin on Linux. [Docker's installation guide](https://docs.docker.com/compose/install/) covers both. Check that Docker is running with `docker version` and `docker compose version`. No host Python installation is needed.

The release images are built for `linux/amd64`. ARM hosts need Docker's amd64 emulation; native ARM images and optional native ARM builds have not been validated. Initial source builds and optional model downloads can take longer than the demo itself.

## Choose a starting point

| Goal | Use |
| --- | --- |
| Try the self-contained demo, run evaluations, or contribute | [Source checkout](#source-checkout). Compose builds local development images. |
| Run the gateway against an existing model server | [Prebuilt release image](#prebuilt-release-image). Compose downloads a versioned gateway image. |
| Add broader ML detection | Complete either setup, then [prepare the optional models](#optional-ml). |

LSDF is the gateway, not a model server. The source demo includes a synthetic upstream; a normal gateway deployment needs an existing OpenAI-compatible upstream.

## Source checkout

Install Git, then run:

```bash
git clone --branch v0.3.1 --depth 1 https://github.com/brntech/lsdf.git
cd lsdf
docker compose build cli
```

Alternatively, download `lsdf-0.3.1-source.zip` from the [v0.3.1 release](https://github.com/brntech/lsdf/releases/tag/v0.3.1), extract it, and open a terminal inside `lsdf-0.3.1`, where `docker-compose.yml` lives. Run `docker compose build cli` there. The tag checkout is detached; contributors should create a branch before editing.

The default `docker-compose.yml` builds `lsdf:dev` from source. You do not need to pull a GHCR image for these commands. Run source commands from this directory; a downloaded container image alone does not provide the demo files, evaluation corpora, or Compose configuration.

Try the full demo:

```bash
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from demo-runner demo-runner
docker compose --profile demo down
```

Success means the demo runner exits 0 and reports passing checks. It intentionally exercises blocking and redaction, writes safe output under `.lsdf/demo/`, and stops the demo services. A first build needs internet access to download base images and Python dependencies. Later cached runs are faster.

To connect a model server instead, start that server, then generate a local configuration:

```bash
docker compose run --rm cli init --upstream lmstudio --output .lsdf.env
docker compose --env-file .lsdf.env up --build -d gateway
```

Use `vllm`, `litellm`, or `openrouter` instead of `lmstudio` as appropriate. For `custom`, also supply `--upstream-base-url`. Edit `.lsdf.env` before starting if your endpoint, profile, or credentials differ. `init` refuses to overwrite an existing file; use `--force` only when replacing it intentionally. See [provider setup](provider-playbook.md).

## Prebuilt release image

Create a directory for the deployment. Download `compose.release.yaml` and `release.env.example` from the [v0.3.1 release assets](https://github.com/brntech/lsdf/releases/tag/v0.3.1) into it. They are also included at the root of the source archive. Copy `release.env.example` to `.lsdf.env`, then edit that file in your text editor.

Set `LSDF_UPSTREAM_BASE_URL` to your running model server. The example uses LM Studio at `http://host.docker.internal:1234`. Add `LSDF_UPSTREAM_API_KEY` if the upstream requires authentication. Keep this file private. The gateway starts with the dependency-light `default` policy.

Run in the directory containing both files:

```bash
docker compose --env-file .lsdf.env -f compose.release.yaml pull
docker compose --env-file .lsdf.env -f compose.release.yaml run --rm gateway doctor --profile default
docker compose --env-file .lsdf.env -f compose.release.yaml up -d
docker compose --env-file .lsdf.env -f compose.release.yaml logs --tail 50 gateway
```

`pull` downloads the selected image; this configuration has no source build or checkout mount. `doctor` checks policy/detector setup; without `--upstream-base-url` it does not check your upstream. Use the live request below to confirm routing.

The release configuration stores generated files in a named volume at `/workspace/.lsdf`. For example:

```bash
docker compose --env-file .lsdf.env -f compose.release.yaml run --rm gateway proof-bundle --output .lsdf/proof --format markdown
```

The files remain in the volume, not in the host checkout. To copy them out after the gateway is running:

```bash
docker compose --env-file .lsdf.env -f compose.release.yaml cp gateway:/workspace/.lsdf/proof ./proof
```

## Which image?

| Image | Purpose |
| --- | --- |
| `ghcr.io/brntech/lsdf:v0.3.1` | Lightweight gateway release. |
| `ghcr.io/brntech/lsdf:v0.3.1-ml` | Same gateway plus ML dependencies and the spaCy model. GLiNER/privacy-filter weights still need preparation. |
| `lsdf:dev`, `lsdf:optional`, `lsdf:runtime` | Local image names built by the source Compose file. They are not GHCR downloads. |

Both published variants belong to the single `ghcr.io/brntech/lsdf` package and start with `default`. An optional image does not automatically enable an ML policy. Set `LSDF_IMAGE` in `.lsdf.env` to select a versioned image, or pin an immutable reference from the release's `image-digests.txt`. `latest` and `latest-ml` are moving aliases; use a version or digest for repeatable deployments.

## Check the connection

Clients use `http://localhost:8080/v1`. Check local management health with `curl http://localhost:8080/lsdf/health` (PowerShell users can use `curl.exe`). A health response is not an accuracy test.

For a real chat request, save this as `request.json`, replacing `YOUR_MODEL_ID` with a model served by your upstream:

```json
{"model":"YOUR_MODEL_ID","messages":[{"role":"user","content":"Reply with a short greeting."}]}
```

```bash
curl -H "Content-Type: application/json" --data-binary "@request.json" http://localhost:8080/v1/chat/completions
```

A successful upstream completion verifies the route. LSDF obtains provider credentials from its configured `LSDF_UPSTREAM_API_KEY`; it does not use a client's placeholder API key as upstream authentication. The Python client example in the README assumes the OpenAI SDK is already installed in your application's environment.

The supplied configurations bind port 8080 to `127.0.0.1`. For a shared deployment, configure a reverse proxy with client authentication and TLS. `LSDF_MANAGEMENT_TOKEN` protects only `/lsdf/*`; it does not authenticate `/v1/chat/completions`. If you set it, include the token in management requests. If management is disabled, those endpoints return 404.

## Host networking and shell settings

Inside a container, `localhost` means that container. Use `host.docker.internal` for a model server on the Docker host, a service name for another container on the same Compose network, or the provider's HTTPS URL. The supplied Compose configurations map `host.docker.internal` through Docker's `host-gateway` support.

On native Linux, the host model server must listen on an address reachable from the Docker bridge; a service bound only to host `127.0.0.1` is generally unreachable from containers. Restrict its access with the host firewall. Docker Desktop networking differs, so verify your actual endpoint with a chat request. [Docker documents host-gateway networking](https://docs.docker.com/reference/cli/docker/container/run/#add-host).

Examples such as `NAME=value docker compose ...` use Bash syntax. On PowerShell, use `$env:NAME = "value"` first, or put settings in `.lsdf.env` and supply `--env-file .lsdf.env` on every relevant Compose command. A Compose env file supplies interpolation values; it does not automatically pass every variable into containers. For one-off CLI commands that need keys, explicitly use `run -e VARIABLE_NAME`. See [vault operations](production-operations.md#encrypted-token-vault).

## Optional ML

Optional dependencies and models have separate licenses; read [third-party notices](../THIRD_PARTY_NOTICES.md). The default path needs no model download. The optional image includes CPU dependencies; it does not include the GLiNER or privacy-filter weights.

For the source checkout, build the optional image and deliberately download both models into its Docker cache:

```bash
docker compose --profile optional build optional-cli
docker compose --profile optional run --rm -e LSDF_GLINER_LOCAL_FILES_ONLY=false -e LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=false optional-cli doctor --profile broad-pii-ml --format json
docker compose --profile optional run --rm -e LSDF_GLINER_LOCAL_FILES_ONLY=true -e LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=true optional-cli doctor --profile broad-pii-ml --format json
```

For the prebuilt deployment, set `LSDF_IMAGE=ghcr.io/brntech/lsdf:v0.3.1-ml` and `LSDF_PROFILE=broad-pii-ml` in `.lsdf.env`, then use the release service with the same download and offline checks:

```bash
docker compose --env-file .lsdf.env -f compose.release.yaml pull
docker compose --env-file .lsdf.env -f compose.release.yaml run --rm -e LSDF_GLINER_LOCAL_FILES_ONLY=false -e LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=false gateway doctor --profile broad-pii-ml --format json
docker compose --env-file .lsdf.env -f compose.release.yaml run --rm -e LSDF_GLINER_LOCAL_FILES_ONLY=true -e LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=true gateway doctor --profile broad-pii-ml --format json
```

Inspect the JSON check named `detectors`: its `families` must include both `gliner` and `openai_privacy_filter` for that full stack. Privacy-filter is optional in the bundled policy, so `doctor` can report success while skipping it. A successful image build or exit code alone is not proof that both models loaded. Keep the two local-files-only settings true for normal operation. Source and release configurations use different named caches; prepare the cache for the configuration you actually deploy.

After the source checks pass, set `LSDF_PROFILE=broad-pii-ml` in your env file. Stop the source gateway before starting the ML variant on the same port:

```bash
docker compose stop gateway
docker compose --env-file .lsdf.env --profile optional up -d gateway-ml
```
For the prebuilt configuration, use `docker compose --env-file .lsdf.env -f compose.release.yaml up -d`.
Stop any existing gateway before starting another on the same host port. Run representative evaluations before enforcement; the release's fresh default/balanced report is not an optional-ML accuracy result.

## Stop, update, and troubleshoot

For source services, use `docker compose down` (include `--profile optional` for `gateway-ml`). For release services, use `docker compose --env-file .lsdf.env -f compose.release.yaml down`. These commands preserve named volumes. Adding `--volumes` deletes stored cache/vault/audit data; it is not part of a routine stop or update.

For an image update, back up persistent data and keys, select the new tag/digest in `.lsdf.env`, run the release `pull` command, then `up -d`. Recheck health and a chat request. Recreating the service applies changed settings; editing an env file alone does not.

| Symptom | Check |
| --- | --- |
| No configuration file found | Open the source folder containing `docker-compose.yml`, or supply `-f compose.release.yaml`. |
| Cannot connect to Docker | Start Docker Desktop/Engine and select Linux containers. |
| Pull denied | Confirm the exact `ghcr.io/brntech/lsdf` image tag and that the package is public. Repository and package visibility are separate. |
| No matching manifest on ARM | The release targets `linux/amd64`; the release Compose file requests that platform and needs emulation on ARM. |
| Port already allocated | Stop the other gateway; release users may change `LSDF_PORT` in `.lsdf.env` and use that port in client URLs. |
| Upstream unavailable / 502 | Check the upstream URL, Docker host routing, model server readiness, and configured provider key. |
| Optional detector missing | Prepare both model caches, inspect active detector families, and verify local-files-only settings. |
| CLI cannot read a vault key | Explicitly pass the key variable with `docker compose run -e`; keep the key out of command literals and committed files. |
