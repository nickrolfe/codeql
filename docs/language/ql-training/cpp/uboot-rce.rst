=====================
CTF: U-Boot challenge
=====================

QL for C/C++

.. container:: semmle-logo

   Semmle :sup:`TM`

.. rst-class:: setup

Setup
=====

For this example you should download:

- `QL for Eclipse <https://help.semmle.com/ql-for-eclipse/Content/WebHelp/install-plugin-free.html>`__
- `U-Boot snapshot <https://downloads.lgtm.com/snapshots/cpp/uboot/u-boot_u-boot_cpp-srcVersion_d0d07ba86afc8074d79e436b1ba4478fa0f0c1b5-dist_odasa-2019-07-25-linux64.zip>`__

.. note::

   For the examples in this presentation, we will be analyzing the `U-Boot loader <https://en.wikipedia.org/wiki/Das_U-Boot>`__.

   You can query the project in `the query console <https://lgtm.com/query/project:1506208346536/lang:cpp/>`__ on LGTM.com.

   .. insert snapshot-note.rst to explain differences between snapshot available to download and the version available in the query console.

   .. include:: ../slide-snippets/snapshot-note.rst

   .. resume slides

Capture the Flag
================

Objective: find the 13 remote-code-execution vulnerabilities that our security researchers found in the U-Boot loader. The vulnerabilities can be triggered when U-Boot is configured to use the network for fetching the next-stage boot resources.

- U-Boot has hundreds of calls to ``memcpy`` and functions that read data from the network (such as ``ntohl`` and ``ntohs``).
- Find them using QL, then gradually refine your query to eliminate *false positives*, i.e. those calls that are safe.
- You should be able to find several vulnerabilities that allow remote code execution of arbitrary code on U-Boot-powered devices.

First Steps
===========

1. In the U-Boot snapshot, ``ntohl``, ``ntohll``, and ``ntohs`` are implemented as macros. Find their definitions.

2. Find all invocations of the ``ntohl``, ``ntohll``, and ``ntohs`` macros.

3. Find the expressions that resulted in these macro invocations.

4. Write another query to find all calls to ``memcpy``.

Taint tracking
==============

We want to find cases where data read from the network is used in a call to ``memcpy``. We can use the taint-tracking library for this.

- Create a configuration class, and define your sources and sinks.

  - Sources should be calls to ``ntohl``, ``ntohll``, or ``ntohs``.
  - The sink should be the size argument of a call to ``memcpy``.

You just found 9 vulnerabilities
================================

What's next?

Some suggestions for improving the query to find more bugs:

- Generalize your query to find other untrusted inputs beyond networking, e.g. the ext4 filesystem.

- There is a call through the function pointer ``udp_packet_handler`` with arguments using ``ntohs``. Can you customize your taint-tracking query to track flow through this call to the various handler functions?