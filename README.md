<a name="top"></a>
<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:E50914,100:0B0B0B&height=200&section=header&text=eos-userutils&fontSize=54&fontColor=ffffff&fontAlignY=38&desc=User%20%26%20group%20utilities%20for%20E-OS&descAlignY=60&descSize=18&animation=fadeIn" alt="eos-userutils"/>
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=19&pause=900&color=E50914&center=true&vCenter=true&width=800&lines=User+%26+group+utilities+for+E-OS;getty+%C2%B7+login+%C2%B7+passwd+%C2%B7+id+%C2%B7+su;The+%27eos+login%3A%27+greeter+prompt" alt="tagline"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-E50914?style=for-the-badge&labelColor=0B0B0B" alt="license"/>
  <img src="https://img.shields.io/badge/Rust-E50914?style=for-the-badge&logo=rust&logoColor=white&labelColor=0B0B0B" alt="Rust"/>
  <img src="https://img.shields.io/badge/part%20of-E--OS-E50914?style=for-the-badge&labelColor=0B0B0B" alt="part of E-OS"/>
</p>

<p align="center"><img src="https://raw.githubusercontent.com/Gh0s777tt/Gh0s777tt/main/assets/divider.svg" width="100%" alt=""/></p>

The `userutils` crate contains the utilities for dealing with users and groups in Redox OS.
They are heavily influenced by UNIX and are, when needed, tailored to specific Redox use cases.

These implementations strive to be as simple as possible drawing particular
inspiration by BSD systems. They are indeed small, by choice.

[![Travis Build Status](https://travis-ci.org/redox-os/userutils.svg?branch=master)](https://travis-ci.org/redox-os/userutils)

**Currently included:**

- `getty`: Used by `init(8)` to open and initialize the TTY line, read a login name and invoke `login(1)`.
- `id`: Displays user identity.
- `login`: Allows users to login into the system
- `passwd`: Allows users to modify their passwords.
- `su`: Allows users to substitute identity.
- `sudo`: Enables users to execute a command as another user.
- `useradd`: Add a user
- `usermod`: Modify user information
- `userdel`: Delete a user
- `groupadd`: Add a user group
- `groupmod`: Modify group information
- `groupdel`: Remove a user group

<p align="center"><img src="https://raw.githubusercontent.com/Gh0s777tt/Gh0s777tt/main/assets/divider.svg" width="100%" alt=""/></p>

<div align="center">

### 🩸 Part of the **GHOST EMPIRE** ecosystem

[**E-OS**](https://github.com/Gh0s777tt/E-OS) · Rust microkernel OS &nbsp;·&nbsp; Minecraft infrastructure suite &nbsp;·&nbsp; Discord &amp; streaming platforms — forged under **Empire Forge**.

<a href="https://discord.gg/Egf88V9UdH"><img src="https://img.shields.io/badge/Discord-Join%20the%20Empire-5865F2?style=for-the-badge&logo=discord&logoColor=white&labelColor=0B0B0B" alt="discord"/></a>
<a href="mailto:ghostt77@empire-forge.com"><img src="https://img.shields.io/badge/Email-Empire%20Forge-E50914?style=for-the-badge&logo=maildotru&logoColor=white&labelColor=0B0B0B" alt="email"/></a>
<a href="https://donatr.ee/ghost77/"><img src="https://img.shields.io/badge/%E2%9D%A4%20Support-Donate-E50914?style=for-the-badge&labelColor=0B0B0B" alt="donate"/></a>

<sub><i>Black. Red. Production-grade. — © GHOST EMPIRE · Empire Forge</i></sub>

</div>
