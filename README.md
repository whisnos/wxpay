微信支付 Python SDK
-------

对[微信支付开发者文档](https://pay.weixin.qq.com/wiki/doc/api/index.html)中给出的API进行了封装。WXPay类下提供了对应的方法：

|方法名 | 说明 |
|--------|--------|
|micropay| 刷卡支付 |
|unifiedorder | 统一下单|
|orderquery | 查询订单 |
|reverse | 撤销订单 |
|closeorder|关闭订单|
|refund|申请退款|
|refundquery|查询退款|
|downloadbill|下载对账单|
|report|交易保障|
|shorturl|转换短链接|
|authcodetoopenid|授权码查询openid|

参数为`dict`类型，返回类型也是`dict`。
方法内部会将参数会转换成含有`appid`、`mch_id`、`nonce_str`和`sign`的XML；
通过HTTPS请求得到返回数据后会对其做必要的处理（例如验证签名，签名错误则抛出异常）。

对于downloadbill，无论是否成功都返回dict类型对象，且都含有`return_code`和`return_msg`。
若成功，其中`return_code`为`SUCCESS`，另外`data`对应对账单数据。

## 兼容性
在Python2.7.6和Python 3.4.3中测试通过。

## 安装

方式1：
```
$ sudo pip install -r requirements.txt
$ sudo python setup.py install
```

方式2:
```
$ sudo pip install pywxpay
```

Python 3使用pip3、python3命令安装。

## 示例
以统一下单为例：
```python
# coding: utf-8
from pywxpay import WXPay
wxpay = WXPay(app_id='wx8888888998', 
              mch_id='8888888',
              key='123434556677888999987766543543322', 
              cert_pem_path='/path/to/apiclient_cert.pem',
              key_pem_path='/path/to/apiclient_key.pem',
              timeout=6.0)
             
wxpay_resp_dict = wxpay.unifiedorder(dict(device_info='WEB',
                                          body='测试商家-商品类目',
                                          detail='',
                                          out_trade_no='2016090910595900000012',
                                          total_fee=1,
                                          fee_type='CNY',
                                          notify_url='http://www.example.com/wxpay/notify',
                                          spbill_create_ip='123.12.12.123',
                                          trade_type='NATIVE')
                                     )

print( wxpay_resp_dict )
