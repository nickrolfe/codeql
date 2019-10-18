==============
CTF: SEGV hunt
==============

QL for C/C++

.. container:: semmle-logo

   Semmle :sup:`TM`

.. rst-class:: setup

Setup
=====

For this example you should download:

- `QL for Eclipse <https://help.semmle.com/ql-for-eclipse/Content/WebHelp/install-plugin-free.html>`__
- `glibc snapshot <https://downloads.lgtm.com/snapshots/cpp/GNU/glibc/bminor_glibc_cpp-srcVersion_333221862ecbebde60dd16e7ca17d26444e62f50-dist_odasa-lgtm-2019-04-08-af06f68-linux64.zip>`__

.. note::

   For the examples in this presentation, we will be analyzing the `GNU C library (glibc) <https://www.gnu.org/software/libc/>`__.

   You can query the project in `the query console <https://lgtm.com/query/project:1506192836820/lang:cpp/>`__ on LGTM.com.

   .. insert snapshot-note.rst to explain differences between snapshot available to download and the version available in the query console.

   .. include:: ../slide-snippets/snapshot-note.rst

   .. resume slides

``alloca()``
============

- Used to allocate a buffer on the stack.

  .. code-block:: cpp

    char *buffer = alloca(256);

- Usually implemented by subtracting the size parameter from the stack pointer and returning the new value of the stack pointer, meaning:

  - The memory is automatically freed when the current function returns.
  - It is extremely fast.

- It is also *unsafe*:

  - It doesn't check if there is enough stack space remaining.
  - If the requested size is too big, it may return an invalid pointer.
  - It's the caller's responsibility to ensure the size isn't too big.

Capture the Flag
================

Objective: find a critical buffer overflow in the GNU C library.

- ``glibc`` has hundreds of calls to ``alloca()``.
- Find them using QL, then gradually refine your query to eliminate *false positives*, i.e. those calls that are safe.
- You should be able to find an unsafe call that is exploitable from a command-line application.

First Steps
===========

1. ``alloca`` is a macro. Find the definition of this macro and the name of the function that it expands to.

2. Find all the calls to this function.

3. Use the ``upperBound`` and ``lowerBound`` predicates from the ``SimpleRangeAnalysis`` library to filter out results that are safe because the allocation size is small.

  - You can classify the allocation size as small if it is less than 65536.
  - Don't forget that negative sizes are very dangerous.

``__libc_use_alloca()``
=======================

The correct way to use ``alloca`` in glibc is to first check that the allocation is safe by calling ``__libc_use_alloca``: 

  .. code-block:: cpp

    char *buffer;
    bool used_alloca;
    if (__libc_use_alloca(size)) {
      buffer = alloca(size);
      used_alloca = true;
    } else {
      buffer = malloc(size);
      used_alloca = false;
    }
    ... /* use buffer */

    if (!used_alloca) {
      free(buffer);
    }

Filtering calls guarded by ``__libc_use_alloca``
================================================

1. Find all calls to ``__libc_use_alloca``.
2. Find all guard conditions where the condition is a call to ``__libc_use_alloca``.
3. Sometimes the return value is assigned to a variable that's used as the guard condition, e.g. at ``setsourcefilter.c:38-41``. Use local dataflow so your query also finds this guard condition.
4. Sometimes the call is wrapped in a call to ``__builtin_expect``, e.g. at ``setenv.c:185``. Customize your dataflow query so it also finds this guard condition.
5. Sometimes the result of ``__libc_use_alloca`` is negated with ``!``, e.g. at ``getaddrinfo.c:2291-2293``. Enhance your query.
6. Now find calls to ``alloca`` that are safe because they are guarded by a call to ``__libc_use_alloca``.

Combining queries
=================

Combine your previous queries to filter out calls to ``alloca`` that:

- Are safe because they use a small allocation size.
- Are safe because they are guarded by a call to ``__libc_use_alloca``.

Taint Tracking
==============

We are interested in calls to ``alloca`` where the allocation size is controlled by a value read from a file.

1. Find calls to ``fopen``.

  - Be aware that ``fopen`` is another macro.
  
2. Write a taint tracking query.

  - The source should be a call to ``fopen``.
  - The sink should be the size argument of an unsafe call to ``alloca``.

.. note:: To help you get started, here is the boilerplate for the query:

  .. code-block:: ql

    /**
    * @kind path-problem
    */

    import cpp
    import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
    import semmle.code.cpp.dataflow.TaintTracking
    import semmle.code.cpp.models.interfaces.DataFlow
    import semmle.code.cpp.controlflow.Guards
    import DataFlow::PathGraph

    // Track taint through `__strnlen`.
    class StrlenFunction extends DataFlowFunction {
      StrlenFunction() { this.getName().matches("%str%len%") }

      override predicate hasDataFlow(FunctionInput i, FunctionOutput o) {
        i.isInParameter(0) and o.isOutReturnValue()
      }
    }

    // Track taint through `__getdelim`.
    class GetDelimFunction extends DataFlowFunction {
      GetDelimFunction() { this.getName().matches("%get%delim%") }

      override predicate hasDataFlow(FunctionInput i, FunctionOutput o) {
        i.isInParameter(3) and o.isOutParameterPointer(0)
      }
    }

    class Config extends TaintTracking::Configuration {
      Config() { this = "fopen_to_alloca_taint" }

      override predicate isSource(DataFlow::Node source) { any() }

      override predicate isSink(DataFlow::Node sink) { any() }
    }

    from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
    where cfg.hasFlowPath(source, sink)
    select sink, source, sink, "fopen flows to alloca"


Bonus: exploiting the bug
===============================

- The GNU C Library includes several command-line applications - our snapshot contains 24 ``main`` functions 
- Demonstrate that the bug is real by showing that you can trigger a SIGSEGV in one of these command-line applications.