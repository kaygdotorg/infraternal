<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Role: the overview of the "Access" section, published at /docs/access/ (D317). One screen: what the section is, where its pages are, and a Planned callout for what is not built. The build adds the list of the section's pages under this text. -->
# Access

Access decides who may reach what: which machine may connect to which, and which person may sign in as which account.

## Two kinds of access

- **Network access** is about machines. It says which machine may open a connection to which other machine in the mesh.
- **Login access** is about people. It says who may become which account on which machine, whether by SSH, in a terminal of Infraternal, or in an app window.

A login needs both: the machine must be allowed to reach the other one, and the person must be allowed to sign in there. Trusting a machine alone never lets one account act as another.

> [!WARNING] Planned
> This describes the design. Pages for network access, login access and privileged access appear when each feature ships.
