package com.xiaomi.keycenter.hsm

import akka.actor.{Props, ActorSystem}
import akka.io.IO
import akka.routing.RoundRobinPool
import com.google.inject.Guice
import spray.can.Http

/**
 * @author huahang
 */
class HsmDemoMain
object HsmDemoMain extends App {
  implicit val system = ActorSystem()
  val handler = system.actorOf(RoundRobinPool(8).props(Props[HsmDemoHandler]), name = "handler")
  IO(Http) ! Http.Bind(handler, interface = "0.0.0.0", port = 20000)
}
