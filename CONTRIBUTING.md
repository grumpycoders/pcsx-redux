# Introduction

## Acknowledgements

Thank you for considering contributing to PCSX-Redux. The main aim of the project is to
be a useful development, debugging, and reverse engineering tool, but any sort of help is greatly
appreciated. There are various areas of the project that can be improved, and lots
of work is still required. Feel free to open a discussion if there's anything
you'd like to talk about.

## Licensing your contribution

By submitting a pull request, you represent that you have the right to license your contribution 
to the PCSX-Redux authors and the community, and agree by submitting the patch that 
your contributions are licensed under the project's license.

## Why should you read this guideline?

Following this guideline will help you to keep contact with the PCSX-Redux team.
This will result in shorter time to process your bug reports, suggestions and pull requests.

## Ways of contributing to PCSX-Redux

You may contribute in a number of ways, including:

* Contributing new features or bugfixes.
* Filing detailed bug reports.
* Suggesting new features.
* Contributing to the [documentation](https://pcsx-redux.consoledev.net/) in the [docs](https://github.com/grumpycoders/pcsx-redux/tree/docs) branch.
* Contributing unit test cases.

# Contributing to PCSX-Redux

## Code of conduct

Please read and follow the [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## Contributing documentation

* Provide improvements as small as possible, as pull requests.
* If a change in documentation structure is needed, we prefer that you file a suggestion.

## Contributing code

* For non-trivial issues or changes, please file an issue where we can discuss the course of action.
* Software pull requests should be as small as possible and providing only one feature per pull request.
* The codebase is using C++-20, so all features from there are fair game, provided it builds on all of the supported platforms. Submitting a pull request should trigger builds for all supported platforms.
* Please try and follow the codestyle, which is enforced by the [clang-format](https://github.com/grumpycoders/pcsx-redux/blob/main/src/.clang-format) rules. Worst case scenario, a bot will issue another PR to fix the codestyle however, so no need to sweat it too much.

## Filing a bug report

If you find a bug, please as much as possible try to file a detailed bug report using the [issue template](https://github.com/grumpycoders/pcsx-redux/issues/new?assignees=&labels=&template=bug_report.yml).
