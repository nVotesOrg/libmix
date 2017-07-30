name := "libmix"
version := "0.2-SNAPSHOT"

scalaVersion := "2.12.3"

resolvers ++= Seq(
  Resolver.sonatypeRepo("releases"),
  Resolver.sonatypeRepo("snapshots")
)

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "3.0.0" % "test",
  "com.squareup.jnagmp" % "jnagmp" % "2.0.0",
  "org.slf4j" % "slf4j-api" % "1.7.25"
  // use this line to build a jar with only nMix + unicrypt
  // "com.squareup.jnagmp" % "jnagmp" % "2.0.0" % "provided"
)

test in assembly := {}
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
scalacOptions += "-opt:l:inline"
javacOptions += "-Xlint:unchecked"