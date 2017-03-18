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

scalaVersion := "2.12.1"

resolvers ++= Seq(
  Resolver.sonatypeRepo("releases"),
  Resolver.sonatypeRepo("snapshots")
)

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "3.0.0" % "test"
)

assemblyMergeStrategy in assembly := {
  case PathList("ch", "bfh", xs @ _*) => MergeStrategy.first
  case x =>
    val oldStrategy = (assemblyMergeStrategy in assembly).value
    oldStrategy(x)
}

scalacOptions ++= Seq("-feature", "-language:existentials", "-deprecation")
javacOptions ++= Seq("-deprecation")
javacOptions += "-Xlint:unchecked"