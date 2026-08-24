# GL.iNet Addon

The GL.iNet addon provides WANSINN support for tested GL.iNet/OpenWrt-based routers.

## Exclusive control

When exclusive control is enabled, WANSINN temporarily stops GL.iNet's integrated
`kmwan` Multi-WAN service for the current router session and takes control of the
routing decisions. WANSINN writes a change record and recovery script before the
takeover so the original router state can be restored.

A router reboot returns GL.iNet's own services to their normal startup behavior.

## SSH access

The setup and router-configuration forms may request the router's SSH password when
WANSINN needs to establish or refresh SSH access. Credential handling is an
implementation detail of the addon and setup path; the UI deliberately does not make
a blanket promise about password persistence.

Do not publish WANSINN runtime state, `.env` files, SSH material, logs, databases, or
router recovery files. The project's `.gitignore` excludes these files from normal
Git tracking.
