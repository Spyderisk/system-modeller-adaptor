# Contributing to the Spyderisk Adaptor Project

Welcome!

We'd love to have your contributions to the Spyderisk Adaptor. This document is about our practical principles of working. 

The overall Spyderisk mission is to:

> increase global trust in Information and Communication Technology (ICT) by establishing an international Open Community supporting the research, development, use and support of open, reliable, accessible and inclusive ICT risk assessment methods and tools.

and you can read more about this in the [general Spyderisk description](https://github.com/Spyderisk/), which explains
who we are and who Spyderisk is intended for.

Please read our [Code of Conduct](../CODE-OF-CONDUCT.md) to keep our community approachable and
respectful.

# Who can contribute?

This Adaptor Project is about the service that offers a higher-level API to the risk reasoner in
the [Spyderisk System Modeller](https://github.com/Spyderisk/system-modeller). You might just be 
wanting to deploy it (using the Docker images provided) or to make changes to the Python code.
Plus of course we welcome fixes to the documentation.

Do please drop us an email to [team@spyderisk.org](mailto://team@spyderisk.org) or open a discussion issue on GitHub.

# Getting started with contributing

You should follow the [Adaptor README](./README.md) to setup a Docker instance
of the service, and try out some simple API calls starting from the
```tests/examples```.  As you explore what we have done you'll be able to see
what needs work.

Alternatively you can find an issue from our
[List of open Adaptor Issues](https://github.com/Spyderisk/system-modeller-adaptor/issues),
or just create a new query or bug report as described in the following section.

Whatever you decide to work on, follow the "How to submit a patch" procedure below

# How to open a query or bug report

* Open a [new issue in system-modeller-adaptor](https://github.com/Spyderisk/system-modeller-adaptor/issues/new)
* Select the template marked "New Spyderisk Deployment query", or "New Spyderisk Deployment bug report"

# How to submit a patch

You are about to make us very happy. There are several cases:

* Documentation fix - [create a fork and send a pull request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request-from-a-fork)
* Obvious code fix - create a fork and pull request, just as for documentation
* Any other code fix - please create a query or bug report according to the previous section. It may well be that you have code which is good to go, but in our young open project there is a lot of context that might be relevant to what you wish to do.

But basically just talk to us using whatever means you are comfortable with, and we will figure it out.

# Spyderisk project principles

## Openness first

* Our [software licensing is Apache 2](./LICENSING.md), and analogously for documentation
* Our communication is collaborative and collective
* We build our software around openly published academic theory

## Transparency trumps accuracy

Spyderisk needs to be both trustable and also to progress quickly. Where there
is incomplete or inaccurate work in the Spyderisk Adaptor code then we document
this with the string:

```
WIP: BRIEF TEXT DESCRIPTION, https://github.com/Spyderisk/system-modeller-adaptor/issues/NNN
```

Where "BRIEF TEXT DESCRIPTION" should not exceed a couple of sentences, and NNN
should be the most relevant issue.

