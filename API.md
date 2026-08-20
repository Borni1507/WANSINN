# WANSINN API v1

Base path:

    /api/v1

Authentication:

    Authorization: Bearer <TOKEN>

Generate, rotate or revoke the token under Config -> Lokale API.
Only the SHA-256 hash is stored in SQLite. The clear-text token is shown once.

## Read endpoints

    GET /api/v1/status
    GET /api/v1/profiles
    GET /api/v1/devices
    GET /api/v1/devices/<id>
    GET /api/v1/groups

## Switch one device

    POST /api/v1/devices/<id>/profile
    Content-Type: application/json

    {"profile":"auto"}

`profile` can be AUTO, OFFLINE or any available WAN profile ID.

OFFLINE requires an explicit second guard:

    {"profile":"offline","confirm_offline":true}

API switching calls the same `switch_device_profile()` function as the web UI.
It therefore keeps Router-first application, DB update-after-success,
AUTO validation, OFFLINE router readback and automation override clearing.

## Switch a group

    POST /api/v1/groups/<id>/profile

    {"profile":"wan2"}

Group operations are best-effort per physical device. The response contains
one result per group member. HTTP 207 is returned when one or more members fail.

## Examples with curl

    curl -H "Authorization: Bearer $WANSINN_TOKEN"       http://wansinn-host:8080/api/v1/devices

    curl -X POST       -H "Authorization: Bearer $WANSINN_TOKEN"       -H "Content-Type: application/json"       -d '{"profile":"auto"}'       http://wansinn-host:8080/api/v1/devices/3/profile

    curl -X POST       -H "Authorization: Bearer $WANSINN_TOKEN"       -H "Content-Type: application/json"       -d '{"profile":"offline","confirm_offline":true}'       http://wansinn-host:8080/api/v1/groups/2/profile

The API token is an administrator-grade secret. Anyone who has it can change
WAN policy and, with the explicit confirmation flag, take devices offline.
