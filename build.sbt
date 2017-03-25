// This file is part of agora-mixnet.
// Copyright (C) 2015-2016  Agora Voting SL <agora@agoravoting.com>

// agora-mixnet is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License.

// agora-mixnet  is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public License
// along with agora-mixnet.  If not, see <http://www.gnu.org/licenses/>.

name := "libmix"
version := "0.2-SNAPSHOT"

scalaVersion := "2.12.1"

resolvers ++= Seq(
  Resolver.sonatypeRepo("releases"),
  Resolver.sonatypeRepo("snapshots")
)

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "3.0.0" % "test",
  "com.squareup.jnagmp" % "jnagmp" % "2.0.0"
  // use this line to build a jar with only nMix + unicrypt
  // "com.squareup.jnagmp" % "jnagmp" % "2.0.0" % "provided"
)

assemblyOption in assembly := (assemblyOption in assembly).value.copy(includeScala = false, includeDependency = true)

assemblyMergeStrategy in assembly := {
  case PathList("ch", "bfh", xs @ _*) => MergeStrategy.first
  case x =>
    val oldStrategy = (assemblyMergeStrategy in assembly).value
    oldStrategy(x)
}

cancelable in Global := true
fork in run := true
envVars in run := Map(
	"nmixlib.gmp" -> "true",
	"nmixlib.extractor" -> "true",
	"nmixlib.parallel-generators" -> "true"
)

scalacOptions ++= Seq("-feature", "-language:existentials", "-deprecation")
javacOptions ++= Seq("-deprecation")
// javacOptions += "-Xlint:unchecked"