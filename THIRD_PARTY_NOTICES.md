# Third-party software notices

SSH-MCP source files written for this project are distributed under the
[Apache License 2.0](LICENSE). Dependencies and base-container components
retain **their own licenses**. Apache-2.0 does not relicense them.

The application depends directly on the following Python distributions.
Exact versions in a built image may vary within the ranges specified in
`pyproject.toml`; consult the image's installed `*.dist-info/METADATA`
for authoritative version and licensing details.

| Package | License indicated by upstream distribution | Source |
| --- | --- | --- |
| AsyncSSH | EPL-2.0 **or** GPL-2.0-or-later | https://github.com/ronf/asyncssh |
| FastAPI | MIT | https://github.com/fastapi/fastapi |
| Uvicorn | BSD-3-Clause | https://github.com/encode/uvicorn |
| HTTPX | BSD-3-Clause | https://github.com/encode/httpx |
| MCP Python SDK | MIT | https://github.com/modelcontextprotocol/python-sdk |
| PyJWT | MIT | https://github.com/jpadilla/pyjwt |

For AsyncSSH, this distribution uses the **EPL-2.0** licensing option.
Preserve its accompanying license text and make the applicable unmodified
AsyncSSH source available through the upstream link above. Modified
versions of that component may have additional source-disclosure
requirements.

Transitive dependencies, Python and Debian packages installed in the
container have separate license obligations; their installed license
notices and distribution metadata must be retained. The shipped Python
environment retains installed `*.dist-info/licenses/` directories.
Review the exact image, SBOM and upstream dependency notices before
redistributing a release image.
