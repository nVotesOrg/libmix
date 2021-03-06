nMixlib Benchmark
=================

Run benchmarks with different vote counts and command line options.

Installation
============

You need gnuplot

     apt-get install gnuplot

Java must be on your path

Set up
======

You must first run

     sbt assembly
     sbt assemblyPackageScala

to generate jars.

At the top of bench.sh set the CLASSPATH and RUN variables accordingly.

     CLASSPATH=../target/scala-2.12/nMixlib-assembly-0.2-SNAPSHOT.jar:../target/scala-2.12/scala-library-2.12.1-assembly.jar
     RUNS="10 20 50"

RUNS is a space separated list of vote counts that will be run.

Use
===

     ./bench.sh

This may take a while depending on the RUNS variable. Once finished a file times.dat will be written. It contains
mix times. You can plot the data with

    gnuplot plot.gpi

which will show the data points as well as a linear fit whose gradient tells you seconds/vote. The graphs are output as png image files. Note that plot.gpi as written expects two runs and therefore two data columns in the data file. You will need to modify if you wish to compare more results.

Use

	 ./run.sh

To execute a single run.