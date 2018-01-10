name := "play-googleauth-example"

version := "0.7.0-SNAPSHOT"

scalaVersion := "2.12.4"

libraryDependencies ++= Seq(
  "com.gu" %% "play-googleauth" % version.value,
  ws
)

lazy val root = (project in file(".")).enablePlugins(PlayScala)
