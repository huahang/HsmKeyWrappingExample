package com.xiaomi.keycenter.hsm

import com.google.gson.Gson
import com.google.inject.Guice
import org.apache.commons.lang3.StringUtils
import org.apache.commons.lang3.exception.ExceptionUtils
import spray.http.HttpResponse
import spray.http.MediaTypes.`application/json`
import spray.http.MediaTypes.`text/plain`
import spray.routing.{ExceptionHandler, HttpServiceActor}
import spray.util.LoggingContext

/**
 * @author huahang
 */

class HsmDemoHandler extends HttpServiceActor {
  val injector = Guice.createInjector(new HsmDemoModule())

  implicit def exceptionHandler(implicit log: LoggingContext) =
    ExceptionHandler {
      case e: Exception => { _ =>
        log.error(e, "Hit an error: " + ExceptionUtils.getStackTrace(e))
        sender() ! HttpResponse(
          status = 500,
          entity = ExceptionUtils.getMessage(e) + "\n"
        )
      }
    }

  val route = {
    post {
      path("rk") {
        parameter('alias) { alias =>
          respondWithMediaType(`application/json`) {
            val service = injector.getInstance(classOf[DemoService])
            service.generateRootKey(alias)
            complete("{}")
          }
        }
      }
    } ~ get {
      path("rk/list") {
        respondWithMediaType(`text/plain`) {
          val service = injector.getInstance(classOf[DemoService])
          complete(StringUtils.join(service.listRootKeys(), "\r\n"))
        }
      }
    }
  }

  override def receive: Receive = runRoute(route)
}
