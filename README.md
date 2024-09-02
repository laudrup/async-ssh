# async-ssh

A C++17 SSH client using Asio and libssh2

**Work in progress**

Not much has been implemented yet. Mostly putting this up to ensure
the basic infrastructure is ready.

## Build status

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/laudrup/async-ssh/linux.yml?branch=master&logo=linux&label=linux)](https://github.com/laudrup/async-ssh/actions/workflows/linux.yml?branch=master) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/laudrup/async-ssh/macos.yml?branch=master&logo=apple&label=macos)](https://github.com/laudrup/async-ssh/actions/workflows/apple.yml?branch=master) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/laudrup/async-ssh/windows.yml?branch=master&logo=windows&label=windows)](https://github.com/laudrup/async-ssh/actions/workflows/windows.yml?branch=master)

# Building

```
cmake -Bbuild
cmake --build build
```

# License
Boost Software License 1.0.

## Contributing

Pull requests, issue reporting etc. are very much welcome.

If you use this library and find it useful, I would love to know. You
should also consider donating to one of the funds that help victims of
the war in Ukraine:

[https://www.stopputin.net/](https://www.stopputin.net/)
