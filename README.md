# WANSINN

**Multi-WAN and DNS control without being locked to a single router platform.**

WANSINN is a free and open-source project for managing and automating
WAN routing and DNS behavior across supported network devices. Router
support is provided through addons, allowing different platforms to work
through the same WANSINN interface and logic.

Current hardware support includes MikroTik and GL.iNet/OpenWrt-based
testing.

> **Current release:** v1.2.0-2
>
> **Project status:** WANSINN is still under active development. Expect
> changes, rough edges, and the occasional router-related adventure.

## Updating WANSINN v1.x

<div style="color:red">

**⚠️ BEST PRACTICE FOR v1.x UPDATES**

To keep your WANSINN configuration and access credentials safe when
updating a v1.x installation:

1. Open **Settings → WANSINN-Config**.
2. Click **Download wansinn.cfg** and keep the exported configuration safe.
3. Perform a fresh installation of the new version with `./install.sh`.
4. Open **Settings → WANSINN-Config** again and load the saved `wansinn.cfg`.
5. Click **Config ersetzen** to restore the configuration.

This fresh-install workflow is the recommended update path for WANSINN
v1.x and preserves the exported configuration as well as the stored
access settings.

</div>

## What WANSINN does

WANSINN provides a central place to control WAN routing, DNS routing and
automated failover behavior.

Depending on the router addon and its capabilities, WANSINN can provide
features such as:

- Multiple WAN connections
- Per-device WAN routing
- Manual WAN selection
- Automatic routing and failover
- WAN health monitoring through WANSINN Medic
- Device discovery
- Router-specific takeover and recovery mechanisms
- Support for multiple router platforms through addons
- Multiple DNS upstream servers
- Per-device DNS routing
- DNS health monitoring and automatic fallback
- Automatic return to the preferred DNS server after recovery
- Internal `.wansinn` DNS records
- Search for DNS routing assignments and internal DNS entries

The goal is not to hide every difference between router manufacturers.
The goal is to give WANSINN a common way to work with them.

## DNS routing

WANSINN can act as the DNS endpoint for clients and select the upstream
resolver based on the requesting device. Devices therefore only need to
use WANSINN as their DNS server while WANSINN handles the actual resolver
selection centrally.

Multiple upstream DNS servers can be configured. A device can be assigned
to a specific resolver, while a default resolver is used where no
individual assignment exists.

### DNS health and automatic fallback

Configured DNS servers are monitored by WANSINN. A resolver can have a
fallback server assigned, allowing WANSINN to switch away from an
unavailable resolver and automatically return when it has recovered.

Health state uses hysteresis so a single lost probe does not immediately
flip the resolver state. The DNS interface shows the current health state
and latency of configured resolvers.

### Internal DNS

WANSINN can answer local `.wansinn` names directly without forwarding
those requests to an upstream resolver. Internal DNS entries can be
managed and searched from the web interface.

## Router addons

Router support is implemented through addons.

This means support for another router or platform does not require
rebuilding WANSINN around that vendor. An addon can translate between
WANSINN and whatever interface the router provides.

Official addons included with WANSINN are part of the WANSINN project
and are distributed under GPL-3.0-or-later.

If you build an addon for another router or platform, I'd love it if you
contributed it back to the project as well, so everyone can find and
benefit from it.

## Why I made this

I made WANSINN for myself, or, more accurately, I let AI build it for
me, and thought I might as well put it out there for everyone.

Found something better? Cool, use that.  
Want to help with the project? Nice, you're welcome to contribute.  
Want to make your own fork? Do it!

If you build an addon for another router or platform, though, I'd love
it if you added it here as well, so everyone can find and benefit from
it.

## Usage of AI

AI was used to write the code for WANSINN. I can read and understand
code, but I can't really write it myself, so I used AI to build the
software I wanted.

You might say: "Well, then it's just AI slop."

I'd disagree.

The code may be AI-generated, but it isn't blindly generated and
published in the hope that it works. WANSINN is tested by a human, me,
on actual network infrastructure and real hardware.

I tested it, broke it, ran into issues, fixed them, changed the design
when something didn't work, and iterated on it repeatedly.

**AI writes the code. I decide what the software should do and test
whether it actually does it.**

## Hardware testing

WANSINN is developed and tested against real network hardware rather
than relying only on simulated environments.

Current testing includes:

- MikroTik
- GL.iNet / OpenWrt

Support for additional platforms can be added through the addon system.

Hardware support should be considered tested only where the project
explicitly says it has been tested.

### MikroTik / RouterOS compatibility

Use WANSINN with a current RouterOS stable or long-term release. RouterOS
7.19.6 was observed on real RB5009 hardware to misroute policy-routed WAN
health-check traffic through the main table even though the WANSINN
mangle rule and custom FIB table were active. The same configuration
behaved correctly after updating RouterOS. Medic warns for RouterOS
versions older than 7.20 so outdated RouterOS is ruled out before WANSINN
routing diagnostics.

### Testing-IP recovery

WANSINN uses an additional local Testing-IP for provider health checks on
platforms that use client-style policy routing. Because this address is
created at runtime, it can disappear after a host or network reboot.
WANSINN checks the configured Testing-IP during startup and restores it
automatically when necessary. If the address disappears while WANSINN is
running, the health probe attempts one automatic recovery before
continuing.

## Release notes

GitHub releases summarize the completed state of a development series.
Intermediate `-XX` builds are iterative development and bug-fix builds,
so their changes may be consolidated into the release notes of the
highest published build rather than documented as separate public
releases.

## License

WANSINN is free software licensed under the **GNU General Public License
version 3 or later (GPL-3.0-or-later).**

Copyright (C) 2026 Felix Bornhöft

You are free to use, study, modify, and redistribute WANSINN under the
terms of the GNU General Public License.

See [LICENSE](LICENSE) for the full license text.

Third-party components and dependencies remain subject to their
respective licenses.

------------------------------------------------------------------------

**Developed with AI. Tested on real hardware.**
