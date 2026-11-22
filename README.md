# Merged into `gcs`

S3 插件既能 publish 也能 checkout：同一目的地一个插件、多个动词。

```groovy
// 旧
runAtom(atom: 'gcs-upload', version: '1.latest', inputs: [...])
// 新（参数名可以原样保留）
runAtom(atom: 'gcs', version: '1.latest', inputs: [action: 'upload', ...])
```

本仓库只读保留，便于历史构建追溯。
