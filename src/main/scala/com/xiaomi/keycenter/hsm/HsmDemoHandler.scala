package com.xiaomi.keycenter.hsm

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

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
        parameter('alias) { alias => { ctx => {
          val service = injector.getInstance(classOf[DemoService])
          val secretKey = service.generateRootKey(alias)
          ctx.complete(
            "ok\r\n" +
              secretKey.getAlgorithm + "\r\n" +
              secretKey.getFormat + "\r\n" +
              BaseEncoding.base16().encode(secretKey.getEncoded) + "\r\n"
          )
        }}}
      } ~ path("generateRootKeyPair") {
        parameter('alias) { alias => { ctx => {
          val service = injector.getInstance(classOf[DemoService])
          val keyPair = service.generateRootKeyPair(alias)
          val publicKey = keyPair.getPublic
          val privateKey = keyPair.getPrivate
          ctx.complete(
            "ok\r\n" +
              "public key" + "\r\n" +
              publicKey.getAlgorithm + "\r\n" +
              publicKey.getFormat + "\r\n" +
              BaseEncoding.base16().encode(publicKey.getEncoded) + "\r\n" +
              "private key" + "\r\n" +
              privateKey.getAlgorithm + "\r\n" +
              privateKey.getFormat + "\r\n" +
              BaseEncoding.base16().encode(privateKey.getEncoded) + "\r\n"
          )
        }}}
      } ~ path("listRootKeys") { ctx => {
        val service = injector.getInstance(classOf[DemoService])
        ctx.complete(StringUtils.join(service.listRootKeys(), "\r\n") + "\r\n")
      }} ~ path("test1") { ctx => {
        val service = injector.getInstance(classOf[DemoService])
        val key = service.generateRootKey("666")
        val cipher = service.encrypt("666", "123".getBytes(Charsets.UTF_8))
        val c = Cipher.getInstance("AES/GCM/NoPadding", "BC")
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec("0102030405060708".getBytes()))
        val raw = new String(c.doFinal(cipher), Charsets.UTF_8)
        ctx.complete(
          raw + "\r\n"
        )
      }}
    }
  }

  override def receive: Receive = runRoute(route)
}
