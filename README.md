# WANSINN

**Multi-WAN control without being locked to a single router platform.**

WANSINN is a free and open-source project for managing and automating
WAN routing across supported network devices. Router support is provided
through addons, allowing different platforms to work through the same
WANSINN interface and logic.

Current hardware support includes MikroTik and GL.iNet/OpenWrt-based
testing.

> **Project status:** WANSINN is still under active development. Expect
> changes, rough edges, and the occasional router-related adventure.

## What WANSINN does

WANSINN provides a central place to control WAN routing and automate
failover behavior.

Depending on the router addon and its capabilities, WANSINN can provide
features such as:

-   Multiple WAN connections
-   Per-device WAN routing
-   Manual WAN selection
-   Automatic routing and failover
-   WAN health monitoring through WANSINN Medic
-   Device discovery
-   Router-specific takeover and recovery mechanisms
-   Support for multiple router platforms through addons

The goal is not to hide every difference between router manufacturers.
The goal is to give WANSINN a common way to work with them.

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

NOTE: ROUTERS SOMETIMES HAVE TO BE MODIFIED TO USE WANSINN (INTERNAL MULTI-WAN ENGINE SHUTDOWN ETC.). WANSINN TRIES TO BE AS UNINTRUSIVE AS POSSIBLE, BUT SOMETIMES IT HAS TO TAKE CONTROL OF CERTAIN SYSTEMS, WHICH MAY LEAD TO THE ROUTER REPORTING A FIRMWARE ISSUE!

## Why I made this

I made WANSINN for myself, or, more accurately, I let AI build it for
me, and thought I might as well put it out there for everyone.

Found something better? Cool, use that.\
Want to help with the project? Nice, you're welcome to contribute.\
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

-   MikroTik CRS310-1G-5S-4S+
-   GL.iNet / OpenWrt (GL-iNet Flint 2 [GL-MT6000])

Support for additional platforms can be added through the addon system.

Hardware support should be considered tested only where the project
explicitly says it has been tested.

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
