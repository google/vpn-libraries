# Google VPN

VPN client library that provides a secure, encrypted tunnel for connected
devices:

*   [Introduction](#introduction)
*   [Current Status](#current-status)
*   [Learn more](#learn-more)
*   [Community contributions](#community-contributions)

## Introduction

Virtual Private Networks (VPNs) are an important tool for users that want to add
a layer of security and privacy to their online activity. It is important for
users to be able to trust that their VPN is implemented with the right
encryption technology and with sound security and privacy. To that end, Google
provides a reference, open source implementation for the VPN used in VPN by
Google One.

The VPN libraries in this repo are currently adopted by the Google One Android
App as of October 2020.

## Current status

The VPN client library is currently available for Android

*Important considerations*: The source code in its current form may not be
buildable and is meant as a reference implementation that is not intended for
direct adoption into other client applications given the dependencies that exist
with other parts of the system. While the team that maintains the project at
Google made a best effort to ensure parity between the open source library and
the version implemented across various clients, we cannot offer explicit
guarantees.

## Learn more

You can learn more about the first implementation of the Google VPN libraries at
https://one.google.com/about/vpn

## Community contributions

At this time the project is not accepting community contributions, however, if
you find a security issue/vulnerability, please report it by going to
https://goo.gl/vulnz to include it in our
[Vulnerability Reward Program](https://www.google.com/about/appsecurity/reward-program/).
