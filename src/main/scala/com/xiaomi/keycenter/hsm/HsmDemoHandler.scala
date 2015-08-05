package com.xiaomi.keycenter.hsm

import com.google.common.base.Charsets
import com.google.common.io.BaseEncoding
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
    get {
      path("generateRootKey") {
        parameter('alias) { alias =>
          val service = injector.getInstance(classOf[DemoService])
          val secretKey = service.generateRootKey(alias)
          complete(
            "ok\r\n" +
              secretKey.getAlgorithm + "\r\n" +
              secretKey.getFormat + "\r\n" +
              BaseEncoding.base16().encode(secretKey.getEncoded) + "\r\n"
          )
        }
      } ~ path("listRootKeys") {
        val service = injector.getInstance(classOf[DemoService])
        complete(StringUtils.join(service.listRootKeys(), "\r\n") + "\r\n")
      } ~ path("test1") {
        val service = injector.getInstance(classOf[DemoService])
        service.generateRootKey("xxx")
        val cipher = service.encrypt("xxx", "123".getBytes(Charsets.UTF_8))
        val raw = new String(service.decrypt("xxx", cipher), Charsets.UTF_8)
        complete(
          raw + "\r\n"
        )
      }
    }
  }

  override def receive: Receive = runRoute(route)
}
