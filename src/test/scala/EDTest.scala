import com.lawsofnature.common.edecrypt.EDecryptUtils
import com.lawsofnature.common.edecrypt.rsa.RSAHexUtils

/**
  * Created by fangzhongwei on 2016/12/3.
  */
object EDTest extends App {
  private val encrypted3desKey: String = RSAHexUtils.encryptByPublic("ABCD1234ABCD1234", RSAHexUtils.PUBLIC_KEY)
  println(encrypted3desKey)
  private val encrypt: String = EDecryptUtils.encrypt("中国123abc", encrypted3desKey, RSAHexUtils.PRIVATE_KEY)
  println(encrypt)
  private val raw: String = EDecryptUtils.decrypt(encrypt, encrypted3desKey, RSAHexUtils.PRIVATE_KEY)
  println(raw)
}