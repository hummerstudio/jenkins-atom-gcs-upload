# jenkins-atom-gcs-upload

用服务账号把构建产物传到 GCS。

两次往返：先用 RS256 自签一个断言换 access token，再带 token 上传。实际踩坑多在第一步——audience 或 scope 写错只会得到一段 400 文本，所以 smoke 的假 token 端点会**用公钥验签并检查 claims**（iss / scope / aud / exp），签名或声明不对当场红。

token 失败与上传失败分开报：前者通常是凭据/配置问题（`USER`），后者是存储端的问题。

```bash
mvn verify   # build + src/test/java/atom/GcsUploadIT.java（对着 tools/fake_gcs.py）
```
