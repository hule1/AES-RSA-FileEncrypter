> **参考链接：**
>
> - [ PyCryptodome’s documentation]:https://pycryptodome.readthedocs.io/en/latest/index.html
>
> - [AES-RSA-FileTransfer]: https://github.com/qux-bbb/AES-RSA-FileTransfer

**依赖包:**     `pip install pycryptodome`

## 一、初始秘钥

​	收发双方均有公私钥,数字签名由私钥办法，以保证数字签名的唯一性；加密文件由公钥加密，以保证只有私钥持有者(通常只是一人)能解密。

![image-20230927145750425](https://fengqingyangosimagedata.oss-cn-nanjing.aliyuncs.com/fengqingyangos/202309271457509.png)



![image-20230927145854374](https://fengqingyangosimagedata.oss-cn-nanjing.aliyuncs.com/fengqingyangos/202309271458418.png)



## 二、具体思路

![image-20230927150526601](https://fengqingyangosimagedata.oss-cn-nanjing.aliyuncs.com/fengqingyangos/202309271505702.png)

