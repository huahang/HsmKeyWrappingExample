package com.xiaomi.keycenter.hsm

import java.io.ByteArrayInputStream
import java.security.{KeyFactory, Key, AlgorithmParameters, KeyPairGenerator, Signature, PrivateKey}
import java.security.spec.ECGenParameterSpec
import java.security.cert.CertificateFactory
import javax.crypto.{SecretKeyFactory, KeyGenerator, Cipher}
import javax.crypto.spec.{SecretKeySpec, IvParameterSpec}

import com.google.common.base.Charsets
import com.google.common.io.BaseEncoding
import com.google.gson.Gson
import com.google.inject.Guice
import com.safenetinc.luna.LunaUtils
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
      } ~ path("generateRootKek") {
        parameter('alias) { alias => { ctx => {
          val service = injector.getInstance(classOf[DemoService])
          val secretKey = service.generateRootKek(alias)
          ctx.complete(
            "ok\r\n" +
              secretKey.getAlgorithm + "\r\n" +
              secretKey.getFormat + "\r\n" +
              BaseEncoding.base16().encode(secretKey.getEncoded) + "\r\n"
          )
        }}}
      } ~ path("getRootKey") {
        parameter('alias) { alias => { ctx => {
          val service = injector.getInstance(classOf[DemoService])
          val key = service.getRootKey(alias)
          ctx.complete(
            "ok\r\n" +
              key.getAlgorithm + "\r\n" +
              key.getFormat + "\r\n" +
              BaseEncoding.base16().encode(key.getEncoded) + "\r\n"
          )
        }}}
      } ~ path("getRootCertificate") {
        parameter('alias) { alias => { ctx => {
          val service = injector.getInstance(classOf[DemoService])
          val certificate = service.getRootCertificate(alias)
          val publicKey = certificate.getPublicKey
          ctx.complete(
            "ok\r\n" +
              "Certificate" + "\r\n" +
              certificate.getType + "\r\n" +
              BaseEncoding.base16().encode(certificate.getEncoded) + "\r\n" +
              "Public key" + "\r\n" +
              publicKey.getAlgorithm + "\r\n" +
              publicKey.getFormat + "\r\n" +
              BaseEncoding.base16().encode(publicKey.getEncoded) + "\r\n"
          )
        }}}
      } ~ path("listRootKeys") { ctx => {
        val service = injector.getInstance(classOf[DemoService])
        ctx.complete(StringUtils.join(service.listRootKeys(), "\r\n") + "\r\n")
      }} ~ path("test1") { ctx => {
        val service = injector.getInstance(classOf[DemoService])
        val cipher = service.encrypt("666", "123".getBytes(Charsets.UTF_8))
        val raw = new String(service.decrypt("666", cipher), Charsets.UTF_8)
        ctx.complete(
          raw + "\r\n"
        )
      }} ~ path("test2") { ctx => {
        val service = injector.getInstance(classOf[DemoService])
        val certificateFactory = CertificateFactory.getInstance("X.509", "BC")
        val certificate = certificateFactory.generateCertificate(
          new ByteArrayInputStream(service.getRootCertificate("root_nistp521_01_cert").getEncoded)
        )
        val data = "hello, world!".getBytes(Charsets.UTF_8)
        val publicKey = certificate.getPublicKey
        val privateKey = service.getRootKey("root_nistp521_01_priv").asInstanceOf[PrivateKey]

        val lunaSignature = Signature.getInstance("SHA256withECDSA", "LunaProvider")
        lunaSignature.initSign(privateKey)
        lunaSignature.update(data)
        val sign = lunaSignature.sign()

        val bcSignature = Signature.getInstance("SHA256withECDSA", "BC")
        bcSignature.initVerify(publicKey)
        bcSignature.update(data)
        val good = bcSignature.verify(sign)

        ctx.complete(
          "ok" + "\r\n" +
            "sign: " + BaseEncoding.base16().encode(sign) + "\r\n" +
            "good: " + good + "\r\n"
        )
      }} ~ path("test3") { ctx => {
        val service = injector.getInstance(classOf[DemoService])
        val certificateFactory = CertificateFactory.getInstance("X.509", "BC")
        val certificate = certificateFactory.generateCertificate(
          new ByteArrayInputStream(service.getRootCertificate("root_rsa2048_01_cert").getEncoded)
        )
        val data = "hello, world!".getBytes(Charsets.UTF_8)
        val publicKey = certificate.getPublicKey
        val privateKey = service.getRootKey("root_rsa2048_01_priv").asInstanceOf[PrivateKey]

        val lunaSignature = Signature.getInstance("SHA256withRSA", "LunaProvider")
        lunaSignature.initSign(privateKey)
        lunaSignature.update(data)
        val sign = lunaSignature.sign()

        val bcSignature = Signature.getInstance("SHA256withRSA", "BC")
        bcSignature.initVerify(publicKey)
        bcSignature.update(data)
        val good = bcSignature.verify(sign)

        ctx.complete(
          "ok" + "\r\n" +
            "sign: " + BaseEncoding.base16().encode(sign) + "\r\n" +
            "good: " + good + "\r\n"
        )
      }} ~ path("test4") { ctx => {
        val service = injector.getInstance(classOf[DemoService])
        val data = "hello, world!".getBytes(Charsets.UTF_8)
        val keyFactory = SecretKeyFactory.getInstance("AES", "SunJCE")
        val secretKey = keyFactory.generateSecret(
          new SecretKeySpec(
            BaseEncoding.base16().decode("DC4EA62FEC88B2A5B1F87D76940CBB9125EC99CFB96DAA683036D8166AAEA760"),
            "AES"
          )
        )
        val encryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "LunaProvider")
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec("0102030405060708".getBytes))
        val cipher = encryptCipher.doFinal(data)
        val keyCipher = service.wrap("666_kek", secretKey)
        val unwrappedKey = service.unwrap("666_kek", keyCipher, secretKey.getAlgorithm, Cipher.SECRET_KEY)
        val decryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "LunaProvider")
        decryptCipher.init(Cipher.DECRYPT_MODE, unwrappedKey, new IvParameterSpec("0102030405060708".getBytes))
        val dataString = new String(decryptCipher.doFinal(cipher), Charsets.UTF_8)

        ctx.complete(
          "ok" + "\r\n" +
            "data string: " + dataString + "\r\n" +
            "secret key:" + "\r\n" + key2string(secretKey) + "\r\n" +
            "unwrapped key:" + "\r\n" + key2string(unwrappedKey) + "\r\n"
        )
      }}
    }
  }

  def key2string(k: Key) = "" +
    k.getAlgorithm + "\r\n" +
    k.getFormat + "\r\n" +
    BaseEncoding.base16().encode(k.getEncoded) + "\r\n"

  override def receive: Receive = runRoute(route)
}
